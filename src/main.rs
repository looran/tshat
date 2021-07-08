/* tshat - chat server for ssh clients
 * Copyright 2021 Laurent Ghigonis <ooookiwi@gmail.com> */

extern crate thrussh;
extern crate thrussh_keys;
extern crate thrussh_libsodium;
extern crate futures;
extern crate tokio;
extern crate anyhow;
extern crate chrono;
extern crate clap;
extern crate regex;
extern crate fork;
extern crate data_encoding;
extern crate log;
extern crate env_logger;
extern crate zeroize;
extern crate md5;
use std::sync::{Mutex, Arc};
use std::str;
use std::mem;
use std::fmt;
use std::io::{self, Read, Write, BufReader, BufRead};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use chrono::{DateTime, Local, TimeZone, NaiveDateTime, Timelike};
use regex::Regex;
use sodiumoxide::crypto::pwhash::argon2id13;
use thrussh_keys::PublicKeyBase64;
use log::{warn, info, debug};
use zeroize::{Zeroize, Zeroizing};

const HISTORY_MAX: usize = 100;

struct Tshat {
    users: HashMap<String, Arc<User>>,
    usersess_map: HashMap<(usize, thrussh::ChannelId), Arc<Mutex<UserSession>>>,
    history: Option<History>,
    keyfp: (String, String), // SHA256 and MD5
    config: Arc<thrussh::server::Config>,
}

#[derive(Debug)]
enum EventType {
    Text,
    Connect,
    Disconnect,
    Command,
    Server,
}

#[derive(Debug)]
struct Event {
    evt: EventType,
    time: DateTime<Local>,
    nick: String,
    text: String,
}

#[derive(Debug)]
struct User {
    name: String,
    passwd_any: bool,
    passwd_hashes: Vec<argon2id13::HashedPassword>,
    keys: Vec<thrussh_keys::key::PublicKey>,
    conf: Mutex<UserConf>,
}

#[derive(Debug)]
struct UserConf {
    bell: bool,
    lastseen: DateTime<Local>,
    active: u16,
}

/// Server handler from thrussh
#[derive(Clone)]
struct Handler {
    conn_id: usize,
    client_addr: Option<std::net::SocketAddr>,
    user: Option<Arc<User>>,
    auth_username: Option<String>,
    tshat: Arc<Mutex<Tshat>>,
    usersess: Option<Arc<Mutex<UserSession>>>,
}

struct UserSession {
    //conn_id: usize,
    client_addr: std::net::SocketAddr,
    user: Arc<User>,
    auth_username: String,
    user_session_num: usize,
    recv_buf: String,
    cursor: u16,
    sendbuf: String,
    handle: thrussh::server::Handle,
    channel: thrussh::ChannelId,
    closing: bool,
    eof: bool,
}

struct History {
    events: Vec<Event>,
    log: Option<File>,
}

fn main() -> Result<(), String> {
    let args = clap::App::new("tshat")
        .version("0.1")
        .about("chat server for ssh clients")
        .after_help("generate a password hash using 2GB of memory (stronger):
$ cat | tr -d '\\n' | argon2 $(openssl rand -base64 18) -id -m 21 -t 1 -e
generate a password hash using 64MB of memory:
$ cat | tr -d '\\n' | argon2 $(openssl rand -base64 18) -id -m 16 -t 3 -e
generate an ssh key:
$ ssh-keygen -f /tmp/mysshkey -t ed25519")
        .setting(clap::AppSettings::ColorNever)
        .arg(clap::Arg::new("debug")
                .short('d')
                .multiple_occurrences(true)
                .about("do not daemonize and log to stdout (twice enables dependencies debugging)"))
        .arg(clap::Arg::new("port")
                .short('p')
                .value_name("port")
                .about("server port to bind, defaults to 2222"))
        .arg(clap::Arg::new("logfile")
                .short('l')
                .value_name("logfile")
                .about("chat log file, default to no file logging"))
        .arg(clap::Arg::new("keyfile")
                .short('k')
                .value_name("keyfile")
                .about("server key file, defaults to .tshat_key and .tshat_key.fp for fingerprint"))
        .arg(clap::Arg::new("serverkeynofile")
                .short('K')
                .about("generate new server key and do not write key/fingerprint to file"))
        .arg(clap::Arg::new("nohistory")
                .short('L')
                .about("do not remember any history"))
        .arg(clap::Arg::new("users")
                .required(true)
                .multiple(true)
                .about("- | <username>:'<password-hash>'|<ssh-pubkey>"))
        .get_matches();
    
    let (daemonize, loglevel, logmodule) = match args.occurrences_of("debug") {
        0 => (true, log::LevelFilter::Info, Some("tshat")),
        1 => (false, log::LevelFilter::Debug, Some("tshat")),
        2 => (false, log::LevelFilter::Debug, None),
        _ => return Err("-d can be specified only once or twice".to_string()),
    };
    env_logger::Builder::new()
        .filter(logmodule, loglevel)
        .format(|buf, record| {
            let module = record.module_path().unwrap_or("");
            match record.level() {
                log::Level::Info => writeln!(buf, "{}", record.args()),
                _ => writeln!(buf, "{}: {}: {}", record.level(), module, record.args()),
            }
        })
        .init();

    sodiumoxide::init().expect("failed to initialize sodiumoxide");

    let keynofile = args.is_present("serverkeynofile");
    let keyfile = args.value_of("keyfile");
    if keynofile && keyfile.is_some() {
        return Err("cannot specify -k and -K at the same time".to_string());
    }
    let keypath = if keynofile {
        None
    } else {
        match keyfile {
            Some(f) => Some(f),
            None => Some(".tshat_key"),
        }
    };

    let (users_map, auth_methods) = {
        let mut stdin_buf = String::new();
        let users_list: Vec<&str> = match args.value_of("users").unwrap() {
            "-" => {
                io::stdin().read_to_string(&mut stdin_buf).expect("could not read stdin");
                stdin_buf.split('\n').collect()
            },
            _ => args.values_of("users").unwrap().collect(),
        };
        parse_users(users_list)?
    };

    let port: u32 = args.value_of_t("port").unwrap_or(2222);
    let addr = format!("0.0.0.0:{}", port);
    info!("listenning on {}", addr);

    let logfile = args.value_of("logfile");
    let nohistory = args.is_present("nohistory");
    if nohistory && logfile.is_some() {
        return Err("cannot specify -l and -L at the same time".to_string());
    }
    
    let tshat = Tshat::new(keypath, users_map, auth_methods, nohistory, logfile)?;

    if daemonize {
        match fork::daemon(false, false) {
            Ok(fork::Fork::Child) => run(tshat, addr),
            Ok(fork::Fork::Parent(_)) => Ok(()),
            Err(e) => Err(format!("failed to daemonize: {}", e))
        }
    } else {
        run(tshat, addr)
    }
}

fn parse_users(users_list: Vec<&str>) -> Result<(HashMap<String, User>, thrussh::MethodSet), String> {
    let mut users_map: HashMap<String, User> = HashMap::new();
    let mut auth_methods = thrussh::MethodSet::empty();
    for user in users_list {
        debug!("parse user: {}", user);
        if user.len() == 0 || user.starts_with("#") {
            continue
        }
        let re = Regex::new(r#"^(?P<username>[0-9A-Za-z\*]+):['"]?(?P<auth>[0-9a-zA-Z,\$= \+/\*\-]+)['"]?$"#).unwrap();
        match re.captures(user) {
            Some(u) => {
                let username = u.name("username").unwrap().as_str().to_string();
                let mut suser = match users_map.entry(username.clone()) {
                    Entry::Occupied(o) => o.into_mut(),
                    Entry::Vacant(v) => v.insert(User::new(username.clone())),
                };
                match u.name("auth") {
                    Some(auth) => {
                        let auths = auth.as_str();
                        debug!("auth:{}", auths);
                        if auths == "*" {
                            if suser.passwd_hashes.len() > 0 {
                                return Err(format!("user {} cannot have any-password when password was specified before", user));
                            }
                            suser.passwd_any = true;
                            auth_methods |= thrussh::MethodSet::KEYBOARD_INTERACTIVE;
                        } else if auths.starts_with("$argon2id$") {
                            if suser.passwd_any {
                                return Err(format!("user {} cannot have password when any-password was specified before", user));
                            }
                            let mut pw = [0; 128];
                            auths.as_bytes()
                                .iter()
                                .enumerate()
                                .for_each(|(i, val)| pw[i] = *val);
                            let hp = argon2id13::HashedPassword(pw);
                            suser.passwd_hashes.push(hp);
                            auth_methods |= thrussh::MethodSet::PASSWORD;
                        } else if auths.starts_with("AAAA") {
                            if suser.passwd_any {
                                return Err(format!("user {} cannot set ssh-key when any-password was specified before", user));
                            }
                            match thrussh_keys::parse_public_key_base64(auths) {
                                Ok(pubkey) => suser.keys.push(pubkey),
                                Err(_) => return Err(format!("user {} has invalid public key", user)),
                            }
                            auth_methods |= thrussh::MethodSet::PUBLICKEY;
                        } else {
                            return Err(format!("user {} cannot parse user authentication entry", user))
                        }
                    },
                    None => return Err(format!("user {} has no valid password / ssh key", user))
                }
            },
            None => return Err(format!("user {} cannot be parsed", user))
        }
    }
    Ok((users_map, auth_methods))
}

fn run(tshat: Tshat, addr: String) -> Result<(), String> {
    let config = Arc::clone(&tshat.config);
    let handler = Handler {
        conn_id: 0,
        client_addr: None,
        user: None,
        auth_username: None,
        tshat: Arc::new(Mutex::new(tshat)),
        usersess: None,
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        debug!("starting ssh server");
        match thrussh::server::run(config, &addr, handler).await {
            Ok(_) => return Ok(()),
            Err(e) => return Err(format!("error running ssh server: {}", e)),
        }
    })
}

/// unused for now
pub fn hash(passwd: &str) -> (String, argon2id13::HashedPassword) {
    sodiumoxide::init().unwrap();
    let hash = argon2id13::pwhash(
        passwd.as_bytes(),
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .unwrap();
    let texthash = std::str::from_utf8(&hash.0).unwrap().to_string();
    (texthash, hash)
}

/// XXX patch thrussh-keys
pub trait MD5Hash {
    fn fingerprint_md5(&self) -> String;
}
impl MD5Hash for thrussh_keys::key::PublicKey {
    fn fingerprint_md5(&self) -> String {
        let key = self.public_key_bytes();
        let mut c = md5::Context::new();
        c.consume(&key[..]);
        c.compute().into_iter()
            .map(|x| format!("{:02x}", x))
            .collect::<Vec<String>>()
            .join(":")
    }
}

impl User {
    fn new(name: String) -> User {
        User {
            name: name,
            passwd_any: false,
            passwd_hashes: Vec::new(),
            keys: Vec::new(),
            conf: Mutex::new(UserConf {
                bell: true,
                lastseen: Local.timestamp(0, 0),
                active: 0,
            }),
        }
    }
    fn auth_password(&self, passwd: &str) -> Result<(), String> {
        if self.passwd_any {
            return Ok(())
        }
        for hash in self.passwd_hashes.iter() {
            if argon2id13::pwhash_verify(&hash, passwd.as_bytes()) {
                return Ok(())
            }
        }
        Err("invalid password".to_string())
    }
    fn auth_pubkey(&self, pubkey: &thrussh_keys::key::PublicKey) -> Result<(), String> {
        for pk in self.keys.iter() {
            if pubkey.public_key_bytes() == pk.public_key_bytes() {
                return Ok(())
            }
        }
        Err("unknown public key".to_string())
    }
    fn auth(&self, password: Option<&str>, pubkey: Option<&thrussh_keys::key::PublicKey>) -> Result<(), String> {
        if password.is_none() && pubkey.is_none() {
            match self.passwd_any {
                true => Ok(()),
                false => Err(format!("Authentication without password not allowed for user {}", self.name)),
            }
        } else if password.is_some() {
            self.auth_password(password.unwrap())
        } else if pubkey.is_some() {
            self.auth_pubkey(pubkey.unwrap())
        } else {
            panic!("auth without arguments!");
        }
    }
    fn get_active(&self) -> u16 {
        let userconf = self.conf.lock().unwrap();
        userconf.active
    }
}

impl Event {
    fn new(evt: EventType, mut time: Option<DateTime<Local>>, nick: String, text: &str) -> Event {
        if time.is_none() {
            time = Some(Local::now().with_nanosecond(0).unwrap());
        }
        Event {
            evt: evt,
            time: time.unwrap(),
            nick: nick,
            text: text.to_string().replace(&['\r', '\n'][..], ""),
        }
    }
    fn parse(s: &str) -> Result<Event, String> {
        let (evt, re) = {
            if let Some(ev) = Regex::new(r#"^(?P<time>[0-9_]+) <(?P<nick>[^>]+)> (?P<text>.*)$"#).unwrap().captures(s) {
                (EventType::Text, ev)
            } else if let Some(ev) = Regex::new(r#"^(?P<time>[0-9_]+) (?P<nick>[^ ]+) connected (?P<text>.*)$"#).unwrap().captures(s) {
                (EventType::Connect, ev)
            } else if let Some(ev) = Regex::new(r#"^(?P<time>[0-9_]+) (?P<nick>[^ ]+) disconnected (?P<text>.*)$"#).unwrap().captures(s) {
                (EventType::Disconnect, ev)
            } else if let Some(ev) = Regex::new(r#"^(?P<time>[0-9_]+) (?P<nick>[^ ]+) (?P<text>/.*)$"#).unwrap().captures(s) {
                (EventType::Command, ev)
            } else if let Some(ev) = Regex::new(r#"^(?P<time>[0-9_]+) >>> tshat server (?P<text>.*)"#).unwrap().captures(s) {
                (EventType::Server, ev)
            } else {
                return Err(format!("cannot parse event: {}", s))
            }
        };
        let time_parsed = &NaiveDateTime::parse_from_str(re.name("time").unwrap().as_str(), "%Y%m%d_%H%M%S")
            .map_err(|_| format!("cannot parse event time : {}", s))?;
        let time = Local.from_local_datetime(&time_parsed).unwrap();
        let nick = match re.name("nick") {
            Some(n) => n.as_str(),
            None => "",
        };
        Ok(Event::new(evt, Some(time), nick.to_string(), re.name("text").unwrap().as_str()))
    }
}

impl Zeroize for Event {
    fn zeroize(&mut self) {
        self.nick.zeroize();
        self.text.zeroize();
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.evt {
            EventType::Text       => write!(f, "{} <{}> {}\r\n", self.time.format("%Y%m%d_%H%M%S"), self.nick, self.text),
            EventType::Connect    => write!(f, "{} {} connected {}\r\n", self.time.format("%Y%m%d_%H%M%S"), self.nick, self.text),
            EventType::Disconnect => write!(f, "{} {} disconnected {}\r\n", self.time.format("%Y%m%d_%H%M%S"), self.nick, self.text),
            EventType::Command    => write!(f, "{} {} {}\r\n", self.time.format("%Y%m%d_%H%M%S"), self.nick, self.text),
            EventType::Server     => write!(f, "{} >>> tshat server {}\r\n", self.time.format("%Y%m%d_%H%M%S"), self.text),
        }
    }
}

impl Tshat {
    fn new(keypath: Option<&str>, users_map: HashMap<String, User>, auth_methods: thrussh::MethodSet, nohistory: bool, logfile: Option<&str>) -> Result<Tshat, String> {
        /* generate or read server keys */
        let secretkey = match keypath {
            Some(keypath) => {
                match File::open(keypath) {
                    Ok(mut keyfile) => {
                        info!("using existing ssh server key from {}", keypath);
                        let mut buf = [0; 64];
                        keyfile.read(&mut buf).expect("could not read from key file");
                        thrussh_libsodium::ed25519::SecretKey { key: buf }
                    },
                    Err(_) => {
                        match OpenOptions::new().mode(0o600).write(true).create(true).open(keypath) {
                            Ok(mut keyfile) => {
                                info!("generating new ssh server key and writing to {}", keypath);
                                let (_, secretkey) = thrussh_libsodium::ed25519::keypair();
                                keyfile.write(&secretkey.key).expect("could not write to key file");
                                secretkey
                            }
                            Err(_why) => return Err(format!("could not open key file for writing generated key: {}", keypath)),
                        }
                    },
                }
            },
            None => {
                info!("generating temporary ssh server key");
                let (_, secretkey) = thrussh_libsodium::ed25519::keypair();
                secretkey
            }
        };
        let keypair = thrussh_keys::key::KeyPair::Ed25519(secretkey.clone());

        /* generate and store server key fingerprint */
        let keyfp_sha256 = format!("SHA256:{}", keypair.clone_public_key().fingerprint());
        let keyfp_md5 = format!("MD5:{}", keypair.clone_public_key().fingerprint_md5());
        let keyfp_txt = format!("server ED25519 fingerprint {}\nserver ED25519 fingerprint {}", keyfp_sha256, keyfp_md5);
        info!("{}", keyfp_txt);
        if let Some(keypath) = keypath {
            let fppath = format!("{}.fp", keypath);
            if let Ok(mut fpfile) = OpenOptions::new().mode(0o600).write(true).create(true).open(&fppath) {
                let keyfp_txtn = format!("{}\n", keyfp_txt);
                fpfile.write(keyfp_txtn.as_bytes()).expect("could not write to key fingerprint file");
            } else {
                return Err(format!("could not open key fingerprint file for writing: {}", fppath));
            }
        }

        /* prepare users map */
        let mut users = HashMap::new();
        for (username, suser) in users_map {
            users.insert(username, Arc::new(suser));
        }
        debug!("users: {:?}", users.keys());

        /* initialize history */
        let history = match nohistory {
            true => None,
            false => {
                let mut history = History::new();
                if let Some(logfile) = logfile {
                    history.load_log(logfile)?;
                    history.update_userconf(&users);
                }
                history.push(Event::new(EventType::Server, None, "".to_string(), "startup"));
                Some(history)
            },
        };

        /* create ssh server configuration */
        let mut config = thrussh::server::Config::default();
        let keypair = thrussh_keys::key::KeyPair::Ed25519(secretkey.clone());
        config.connection_timeout = None; // by default openssh does not send keepalives
        config.auth_rejection_time = std::time::Duration::from_secs(2);
        config.server_id = "SSH-2.0--".to_string();
        config.methods = auth_methods;
        config.keys.push(keypair);

        /* create Tshat */
        Ok(Tshat {
            users: users,
            usersess_map: HashMap::new(),
            history: history,
            keyfp: (keyfp_sha256, keyfp_md5),
            config: Arc::new(config),
        })
    }

    /// attempts authentication of a user to the server, using password or public key
    /// if the user is not found, the wildcard user is also tried if present
    fn auth(&self, user: &str, password: Option<&str>, pubkey: Option<&thrussh_keys::key::PublicKey>) -> Result<Arc<User>, String> {
        let suser = match self.users.contains_key(user) {
            true => self.users.get(user),
            false => self.users.get("*"),
        };
        match suser {
            Some(suser) => {
                match suser.auth(password, pubkey) {
                    Ok(_) => Ok(suser.clone()),
                    Err(e) => Err(e),
                }
            },
            None => Err("user does not exist".to_string()),
        }
    }

    /// returns an empty session number for users authenticated under a specific user name
    /// it is used to create the nickname of a user when multiple users have the same name
    fn get_user_session_num(&self, username: &str) -> usize {
        let used_nums: Vec<usize> = self.usersess_map.values().into_iter()
            .filter_map(|usersess| {
                let usersess = usersess.lock().unwrap();
                match usersess.auth_username == username {
                    true => Some(usersess.user_session_num),
                    false => None,
                }
            }).collect();
        for i in 0..mem::size_of::<usize>() {
            if used_nums.iter().find(|&&x| i == x).is_none() {
                return i;
            }
        }
        panic!("exausted user_session_num");
    }
}

impl History {
    fn new() -> History{
        History {
            events: Vec::new(),
            log: None,
        }
    }

    fn load_log(&mut self, path: &str) -> Result<(), String> {
        debug!("History load_log");
        let log = match OpenOptions::new().mode(0o600).read(true).append(true).create(true).open(path) {
            Err(why) => return Err(format!("couldn't open log file {}: {}", path, why)),
            Ok(file) => file,
        };
        let mut reader = BufReader::new(log);
        let mut buffer = String::new();
        while let Ok(len) = reader.read_line(&mut buffer) {
            if len == 0 {
                break;
            }
            match Event::parse(&buffer[..len-1]) {
                Ok(event) => self.push(event),
                Err(e) => warn!("History load_log parse event failed: {}", e),
            }
            buffer.clear();
        }
        self.log = Some(reader.into_inner());
        Ok(())
    }

    fn push(&mut self, event: Event) {
        if let Some(mut log) = self.log.as_ref() {
            log.write_all(event.to_string().as_bytes()).expect("History push write failed");
        };
        self.events.push(event);
    }

    /// read history log and update users configuration
    fn update_userconf(&self, users: &HashMap<String, Arc<User>>) {
        for ev in &self.events {
            if let Some(user) = &users.get(&ev.nick) {
                let mut userconf = user.conf.lock().unwrap();
                /* update last seen */
                if ev.time > userconf.lastseen {
                    userconf.lastseen = ev.time;
                }
                /* update bell */
                if matches!(ev.evt, EventType::Command) {
                    match ev.text.as_str() {
                        "/bell" => userconf.bell = true,
                        "/nobell" => userconf.bell = false,
                        _ => (),
                    }
                }
            }
        }
    }
}

impl thrussh::server::Server for Handler {
    type Handler = Self;
    fn new(&mut self, addr: Option<std::net::SocketAddr>) -> Self {
        // XXX check conn_id overflow
        let mut s = self.clone();
        self.conn_id += 1;
        s.client_addr = addr;
        debug!("Handler new self.conn_id={} s.id={}", self.conn_id, s.conn_id);
        s
    }
}

impl thrussh::server::Handler for Handler {
    type Error = anyhow::Error;
    type FutureAuth = futures::future::Ready<Result<(Self, thrussh::server::Auth), anyhow::Error>>;
    type FutureUnit = futures::future::Ready<Result<(Self, thrussh::server::Session), anyhow::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, thrussh::server::Session, bool), anyhow::Error>>;

    fn finished_auth(self, auth: thrussh::server::Auth) -> Self::FutureAuth {
        futures::future::ready(Ok((self, auth)))
    }
    fn finished_bool(self, b: bool, s: thrussh::server::Session) -> Self::FutureBool {
        futures::future::ready(Ok((self, s, b)))
    }
    fn finished(self, s: thrussh::server::Session) -> Self::FutureUnit {
        futures::future::ready(Ok((self, s)))
    }

    fn auth_keyboard_interactive(mut self, user: &str, submethods: &str, response: Option<thrussh::server::Response>) -> Self::FutureAuth {
        debug!("XXX auth_keyboard_interactive user={} submethods={} response={:?}", user, submethods, response);
        let res = {
            let tshat = self.tshat.lock().expect("internal error: cannot lock on tshat");
            tshat.auth(user, None, None)
        };
        match res {
            Ok(suser) => {
                debug!("auth_keyboard_interactive: authenticated successfully for user '{}'", user);
                self.user = Some(suser);
                self.auth_username = Some(user.to_string());
                self.finished_auth(thrussh::server::Auth::Accept)
            },
            Err(e) => {
                debug!("auth_keyboard_interactive: rejected user '{}' : {}", user, e);
                self.finished_auth(thrussh::server::Auth::Reject)
            },
        }
    }

    fn auth_publickey(mut self, user: &str, pubkey: &thrussh_keys::key::PublicKey) -> Self::FutureAuth {
        let res = {
            let tshat = self.tshat.lock().expect("internal error: cannot lock on tshat");
            tshat.auth(user, None, Some(pubkey))
        };
        match res {
            Ok(suser) => {
                debug!("auth_publickey: authenticated successfully for user '{}' pubkey '{}': {:?}", user, pubkey.fingerprint(), pubkey);
                self.user = Some(suser);
                self.auth_username = Some(user.to_string());
                self.finished_auth(thrussh::server::Auth::Accept)
            },
            Err(e) => {
                debug!("auth_publickey: rejected user '{}' pubkey '{}' {:?} : {}", user, pubkey.fingerprint(), pubkey, e);
                self.finished_auth(thrussh::server::Auth::Reject)
            },
        }
    }

    fn auth_password(mut self, user: &str, password: &str) -> Self::FutureAuth {
        let res = {
            let tshat = self.tshat.lock().expect("internal error: cannot lock on tshat");
            tshat.auth(user, Some(password), None)
        };
        match res {
            Ok(suser) => {
                debug!("auth_password: authenticated successfully for user '{}'", user);
                self.user = Some(suser);
                self.auth_username = Some(user.to_string());
                self.finished_auth(thrussh::server::Auth::Accept)
            },
            Err(e) => {
                debug!("auth_password: rejected user '{}' : {}", user, e);
                self.finished_auth(thrussh::server::Auth::Reject)
            },
        }
    }

    fn channel_open_session(mut self, channel: thrussh::ChannelId, session: thrussh::server::Session) -> Self::FutureUnit {
        match self.user {
            Some(ref u) => {
                debug!("channel_open_session: {} from {} : conn_id={} channel={:?}", u.name, self.client_addr.unwrap().to_string(), self.conn_id, channel);
                if let Ok(mut tshat) = self.tshat.lock() {
                    if tshat.usersess_map.contains_key(&(self.conn_id, channel)) {
                        warn!("channel already open !");
                    } else {
                        if let Some(ref auth_username) = self.auth_username {
                            let mut usersess = UserSession::new(self.conn_id, self.client_addr.unwrap(), u.clone(), auth_username, tshat.get_user_session_num(auth_username), channel, session.handle());
                            let event = Event::new(EventType::Connect, None, usersess.nick(), &format!("from {}", usersess.client_addr.to_string()));
                            for ((_, _), us) in tshat.usersess_map.iter_mut() {
                                let mut us = us.lock().unwrap();
                                us.sendbuf_prompt_hide();
                                us.sendbuf_push_line(&event);
                                us.sendbuf_prompt_restore();
                                us.sendbuf_send();
                            }
                            if let Some(ref mut history) = tshat.history {
                                history.push(event);
                            }
                            usersess.connect();
                            usersess.sendbuf_push_welcome(&tshat.users);
                            let lastseen = {
                                match usersess.user.name.as_str() {
                                    "*" => None,
                                    _ => Some(usersess.user.conf.lock().unwrap().lastseen),
                                }
                            };
                            if let Some(ref mut history) = tshat.history {
                                usersess.sendbuf_push_history(&history, lastseen, true);
                            }
                            usersess.sendbuf_push_prompt();
                            usersess.sendbuf_send();
                            usersess.update_lastseen();
                            let usersess = Arc::new(Mutex::new(usersess));
                            self.usersess = Some(usersess.clone());
                            tshat.usersess_map.insert((self.conn_id, channel), usersess.clone());
                        } else {
                            warn!("channel_open_session auth_username not set");
                        }
                    }
                } else {
                    panic!("cannot lock tshat");
                }
            },
            None => {
                warn!("channel_open_session has no user in session");
            }
        };
        self.finished(session)
    }

    fn data(self, channel: thrussh::ChannelId, data: &[u8], session: thrussh::server::Session) -> Self::FutureUnit {
        let mut did_broadcast = false;
        debug!("data from user {:?} [{}-{:?}] : {:02X?} = {}", self.auth_username.as_ref(), self.conn_id, channel, data, str::from_utf8(data).unwrap().to_string());

        if let Ok(mut tshat) = self.tshat.lock() {
            if let Some(usersess) = self.usersess.as_ref() {
                if let Ok(mut usersess) = usersess.lock() {
                    for c in data {
                        match *c {
                            0x20..=0x7e => {
                                /* printable character */
                                usersess.sendbuf.push(*c as char);
                                usersess.recv_buf.push(*c as char);
                                usersess.cursor += 1;
                            },
                            0x0d => {
                                /* enter */
                                if usersess.recv_buf.chars().nth(0) == Some('/') {
                                    /* command */
                                    let event = Event::new(EventType::Command, None, usersess.nick(), &usersess.recv_buf.clone());
                                    if let Some(ref mut history) = tshat.history {
                                        history.push(event);
                                    }
                                    match usersess.recv_buf.as_str() {
                                        "/help" => {
                                            if tshat.history.is_some() {
                                                usersess.sendbuf.push_str("\r\n/history    print all chat history");
                                            }
                                            if usersess.user.name != "*" {
                                                usersess.sendbuf.push_str("\r\n/bell       enable message bell notification");
                                                usersess.sendbuf.push_str("\r\n/nobell     disable message bell notification");
                                                usersess.sendbuf.push_str("\r\n/conf       show user configuration");
                                            }
                                            usersess.sendbuf.push_str("\r\n/users      list allowed users and active connections");
                                            usersess.sendbuf.push_str("\r\n/fp         show server key fingerprint");
                                            usersess.sendbuf.push_str("\r\n/quit       exit chat (shortcut: ctrl-d)");
                                            usersess.sendbuf.push_str("\r\n");
                                        },
                                        "/history" => {
                                            usersess.sendbuf.push_str("\r\n");
                                            if let Some(ref mut history) = tshat.history {
                                                usersess.sendbuf_push_history(&history, None, false);
                                            }
                                        },
                                        "/bell" => {
                                            usersess.sendbuf.push_str("\r\n");
                                            if usersess.user.name != "*" {
                                                usersess.sendbuf.push_str("bell enabled\r\n");
                                                let mut userconf = usersess.user.conf.lock().unwrap();
                                                userconf.bell = true;
                                            }
                                        },
                                        "/nobell" => {
                                            usersess.sendbuf.push_str("\r\n");
                                            if usersess.user.name != "*" {
                                                usersess.sendbuf.push_str("bell disabled\r\n");
                                                let mut userconf = usersess.user.conf.lock().unwrap();
                                                userconf.bell = false;
                                            }
                                        },
                                        "/conf" => {
                                            usersess.sendbuf.push_str("\r\n");
                                            if usersess.user.name != "*" {
                                                let (bell, lastseen) = {
                                                    let userconf = usersess.user.conf.lock().unwrap();
                                                    (userconf.bell, userconf.lastseen)
                                                };
                                                let s = format!(concat!("user {} configuration:\r\n",
                                                            "bell: {}\r\n",
                                                            "lastseen: {}\r\n"), usersess.user.name, bell, lastseen.format("%Y%m%d_%H%M%S"));
                                                usersess.sendbuf.push_str(&s);
                                            }
                                        },
                                        "/users" => {
                                            usersess.sendbuf.push_str("\r\n");
                                            usersess.sendbuf_push_users(&tshat.users);
                                        },
                                        "/fp" => {
                                            let s = format!(concat!("\r\nserver ED25519 fingerprint {}\r\n",
                                                        "server ED25519 fingerprint {}\r\n"), &tshat.keyfp.0, &tshat.keyfp.1);
                                            usersess.sendbuf.push_str(&s);
                                        },
                                        "/quit" => {
                                            usersess.sendbuf.push_str("\r\ngoodbye\r\n");
                                            usersess.closing = true;
                                        },
                                        _ => {
                                            usersess.sendbuf.push_str("\r\ncommand not understood\r\n");
                                        },
                                    }
                                } else {
                                    /* normal text */
                                    let event = Event::new(EventType::Text, None, usersess.nick(), &usersess.recv_buf.clone());
                                    /* print text locally */
                                    usersess.sendbuf_prompt_hide();
                                    usersess.sendbuf_push_line(&event);
                                    /* broadcast text */
                                    for ((us_connid, us_channel), us) in tshat.usersess_map.iter_mut() {
                                        if !(*us_connid == self.conn_id && *us_channel == channel) {
                                            let mut us = us.lock().unwrap();
                                            us.sendbuf_prompt_hide();
                                            us.sendbuf_push_line(&event);
                                            if us.user.conf.lock().unwrap().bell {
                                                us.sendbuf_push_bell();
                                            }
                                            us.sendbuf_prompt_restore();
                                        }
                                    }
                                    /* store text in history */
                                    if let Some(ref mut history) = tshat.history {
                                        history.push(event);
                                    }
                                    did_broadcast = true;
                                }
                                /* new prompt */
                                usersess.sendbuf_push_prompt();
                            },
                            0x7f => {
                                /* del */
                                if usersess.cursor > 2 {
                                    usersess.sendbuf.push_str("\x08 \x08");
                                    usersess.recv_buf.pop();
                                    usersess.cursor -= 1;
                                }
                            },
                            0x03 => {
                                /* ctr-c */
                                usersess.sendbuf_prompt_hide();
                                usersess.sendbuf_push_prompt();
                            },
                            0x04 => {
                                /* ctr-d */
                                if usersess.cursor == 2 {
                                    usersess.sendbuf.push_str("\r\ngoodbye\r\n");
                                    usersess.closing = true;
                                }
                            },
                            _ => (),
                        }
                    }
                    usersess.sendbuf_send();
                    usersess.update_lastseen();
                }
            }
            if did_broadcast {
                for ((us_connid, us_channel), us) in tshat.usersess_map.iter_mut() {
                    if !(*us_connid == self.conn_id && *us_channel == channel) {
                        let mut us = us.lock().unwrap();
                        us.sendbuf_send();
                    }
                }
            }
        } else {
            panic!("cannot lock tshat");
        }
        self.finished(session)
    }

    fn extended_data(self, _channel: thrussh::ChannelId, _ext: u32, _data: &[u8], session: thrussh::server::Session) -> Self::FutureUnit {
        debug!("extended_data from user {:?}", self.user.as_ref());
        self.finished(session)
    }

    fn pty_request(
        self,
        channel: thrussh::ChannelId,
        term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        modes: &[(thrussh::Pty, u32)],
        mut session: thrussh::server::Session,
    ) -> Self::FutureUnit {
        debug!("pty_request {} {:?}", term, modes);
        // we don't want to be rude and prevent ssh some client to connect
        // (like Termius)
        session.channel_success(channel);
        self.finished(session)
    }

    fn shell_request(self, channel: thrussh::ChannelId, mut session: thrussh::server::Session) -> Self::FutureUnit {
        debug!("shell_request");
        // we don't want to be rude and prevent ssh some client to connect
        // (like Termius)
        session.channel_success(channel);
        self.finished(session)                              
    }

    fn channel_close(mut self, channel: thrussh::ChannelId, session: thrussh::server::Session) -> Self::FutureUnit {
        debug!("channel_close from user {:?} {} {:?}", self.user.as_ref(), self.conn_id, channel);
        if let Ok(mut tshat) = self.tshat.lock() {
            if let Some(usersess) = self.usersess {
                let mut usersess = usersess.lock().unwrap();
                let reason = match usersess.eof {
                    true => "(timeout)",
                    false => {
                        usersess.update_lastseen();
                        ""
                    }
                };
                usersess.disconnect();
                let event = Event::new(EventType::Disconnect, None, usersess.nick(), reason);
                for ((us_connid, us_channel), us) in tshat.usersess_map.iter_mut() {
                    if !(*us_connid == self.conn_id && *us_channel == channel) {
                        let mut us = us.lock().unwrap();
                        us.sendbuf_prompt_hide();
                        us.sendbuf_push_line(&event);
                        us.sendbuf_prompt_restore();
                        us.sendbuf_send();
                    }
                }
                if let Some(ref mut history) = tshat.history {
                    history.push(event);
                }
                tshat.usersess_map.remove(&(self.conn_id, channel));
                self.usersess = None;
            } else {
                warn!("channel_close() called on non-existent user session : {} {:?}", self.conn_id, channel);
            }
        } else {
            panic!("cannot lock tshat");
        }
        self.finished(session)
    }

    fn channel_eof(self, _channel: thrussh::ChannelId, session: thrussh::server::Session) -> Self::FutureUnit {
        debug!("channel_eof from user {:?}", self.user.as_ref());
        if let Some(ref usersess) = self.usersess {
            let mut usersess = usersess.lock().unwrap();
            usersess.eof = true;
        }
        self.finished(session)
    }
}

impl UserSession {
    fn new(_conn_id: usize, client_addr: std::net::SocketAddr, user: Arc<User>, auth_username: &str, user_session_num: usize, channel: thrussh::ChannelId, handle: thrussh::server::Handle) -> UserSession {
        UserSession {
            //conn_id: conn_id,
            client_addr: client_addr,
            user: user.clone(),
            auth_username: auth_username.to_string(),
            user_session_num: user_session_num,
            recv_buf: String::new(),
            cursor: 0,
            sendbuf: String::new(),
            channel: channel,
            handle: handle,
            closing: false,
            eof: false,
        }
    }

    /// generate a nickname for a connecting user
    fn nick(&self) -> String {
        let mut nick = String::new();
        if self.user.name.as_str() == "*" {
            nick.push_str("*");
        };
        nick.push_str(&self.auth_username);
        if self.user_session_num > 0 {
            nick.push_str(&format!("({})", self.user_session_num));
        }
        nick
    }

    fn update_lastseen(&self) {
        let mut userconf = self.user.conf.lock().unwrap();
        userconf.lastseen = Local::now().with_nanosecond(0).unwrap();
    }

    /// XXX very ugly way to send to other clients by getting entering the tokio runtime mannually to send data
    /// see https://nest.pijul.com/pijul/thrussh/discussions/38#69cdeb44-99b5-4b78-8a48-6ea2f9fcce8f
    //fn asyncsim_send(handle: &thrussh::server::Handle, channel: thrussh::ChannelId, bytes: &[u8], mut close_after_send: bool) {
    fn asyncsim_send(handle: &thrussh::server::Handle, channel: thrussh::ChannelId, buf: thrussh::CryptoVec, mut close_after_send: bool) {
        let tokiohandle = tokio::runtime::Handle::current();
        let mut sess = handle.clone();
        tokiohandle.spawn(async move {
            match sess.data(channel, buf).await {
                Ok(_) => (),
                Err(_) => {
                    debug!("detected error while send, closing connection");
                    close_after_send = true;
                },
            }
            if close_after_send {
                match sess.close(channel).await {
                    Ok(_) => (),
                    Err(_) => warn!("detected error while close"),
                    // XXX communicate with Tshat to indicate that user did disconnect
                }
            }
        });
    }

    fn sendbuf_push_line(&mut self, line: &Event) {
        self.sendbuf.push_str(&Zeroizing::new(line.to_string()));
    }
    fn sendbuf_prompt_hide(&mut self) {
        for _ in 0..(self.cursor+2) {
            self.sendbuf.push_str("\x08 \x08");
        }
    }
    fn sendbuf_prompt_restore(&mut self) {
        self.sendbuf.push_str("> ");
        self.sendbuf.push_str(&self.recv_buf);
    }
    fn sendbuf_push_history(&mut self, history: &History, since: Option<DateTime<Local>>, truncate: bool) {
        /* print a header above history */
        let intro = match since {
            Some(since) => {
                if since == Local.timestamp(0, 0) {
                    "history since server startup:\r\n".to_string()
                } else {
                    format!("history since last seen at {}:\r\n", since.format("%Y%m%d_%H%M%S"))
                }
            },
            None => format!("history since server startup:\r\n"),
        };
        self.sendbuf.push_str(&intro);
        /* build a list of events we should show */
        let mut events = Vec::new();
        for ev in &history.events {
            if since.is_none() || (ev.time >= since.unwrap()) {
                match ev.evt {
                    EventType::Command => (),
                    _ => events.push(ev),
                }
            }
        }
        /* limit events count to HISTORY_MAX */
        let from = if truncate && events.len() >= HISTORY_MAX {
            events.len() - HISTORY_MAX
        } else {
            0
        };
        if from > 0 {
            let s = format!("[... {} events above ...]\r\n", from);
            self.sendbuf.push_str(&s);
        }
        /* show the events */
        for ev in &events[from..] {
            self.sendbuf.push_str(&Zeroizing::new(ev.to_string()));
        }
    }
    fn sendbuf_push_welcome(&mut self, users: &HashMap<String, Arc<User>>) {
        self.sendbuf.push_str(">>> welcome ");
        self.sendbuf.push_str(&self.nick());
        self.sendbuf.push_str("\r\n>>> ");
        self.sendbuf_push_users(users);
        self.sendbuf.push_str(">>> type /help to list available commands\r\n");
    }
    fn sendbuf_push_users(&mut self, users: &HashMap<String, Arc<User>>) {
        let mut s = String::new();
        self.sendbuf.push_str("users allowed in the room: ");
        for (_, u) in users {
            let us = format!("{}[{}] ", u.name, u.clone().get_active());
            s.push_str(&us);
        }
        self.sendbuf.push_str(&s);
        self.sendbuf.push_str("\r\n");
    }
    fn sendbuf_push_bell(&mut self) {
        self.sendbuf.push_str("\x07");
    }
    fn sendbuf_push_prompt(&mut self) {
        self.recv_buf.zeroize();
        self.recv_buf.clear();
        self.sendbuf.push_str("> ");
        self.cursor = 2;
    }
    fn sendbuf_send(&mut self) {
        if self.sendbuf.len() > 0 {
            UserSession::asyncsim_send(&self.handle, self.channel, thrussh::CryptoVec::from_slice(self.sendbuf.as_bytes()), self.closing);
            self.sendbuf.zeroize();
            self.sendbuf.clear();
        }
    }
    fn connect(&mut self) {
        let mut userconf = self.user.conf.lock().unwrap();
        userconf.active += 1;
    }
    fn disconnect(&mut self) {
        let mut userconf = self.user.conf.lock().unwrap();
        userconf.active -= 1;
    }
}
