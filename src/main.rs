use inotify::{EventMask, Inotify, WatchMask};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant};

const TIME_LIMIT: u64 = 300;
const RATE_LIMIT: usize = 3;

struct Watched<'a> {
    path: &'a Path,
    file: &'a OsStr,
    dir: &'a Path,
    pos: u64,
}

impl<'a> Watched<'a> {
    fn new<P: AsRef<Path> + ?Sized>(f: &'a P) -> Self {
        Watched {
            path: f.as_ref(),
            file: f.as_ref().file_name().unwrap_or_else(|| OsStr::new("")),
            dir: f.as_ref().parent().unwrap_or_else(|| Path::new("/")),
            pos: 0,
        }
    }

    fn set_pos(&mut self, n: u64) {
        self.pos = n;
    }
}

#[derive(Debug)]
enum Auth {
    Sudo,
    System,
}

#[derive(Debug)]
struct FailureMap {
    auth_type: Auth,
    auth_time: Vec<Instant>,
}

impl FailureMap {
    fn new(a: Auth) -> Self {
        FailureMap {
            auth_type: a,
            auth_time: vec![],
        }
    }

    fn add(&mut self) {
        self.auth_time.push(Instant::now());
    }

    fn clean(&mut self) {
        self.auth_time
            .retain(|x| x.elapsed() <= Duration::from_secs(TIME_LIMIT));
    }
}

struct AuthFailure {
    kind: Auth,
    message: String,
}

fn main() -> Result<(), io::Error> {
    let mut watch = Watched::new("/var/log/auth.log");

    let mut inotify = Inotify::init().expect("Failed to initialize inotify");

    inotify.add_watch(&watch.dir, WatchMask::CREATE | WatchMask::MOVED_FROM)?;

    if watch.path.is_file() {
        let meta = fs::metadata(&watch.path)?;
        watch.set_pos(meta.len());
        inotify.add_watch(&watch.path, WatchMask::MODIFY | WatchMask::MOVE_SELF)?;
    }

    let sudo_failure = AuthFailure {
        kind: Auth::Sudo,
        message: String::from("pam_unix(sudo:auth): authentication failure;"),
    };
    let systemauth_failure = AuthFailure {
        kind: Auth::System,
        message: String::from("pam_unix(system-auth:auth): authentication failure;"),
    };

    let mut sudo_map = FailureMap::new(sudo_failure.kind);
    let mut system_map = FailureMap::new(systemauth_failure.kind);

    let mut linebuffer = vec![];

    let mut buffer = [0u8; 4096];

    loop {
        let events = inotify.read_events_blocking(&mut buffer)?;

        for event in events {
            if Some(OsStr::new(watch.file)) == event.name {
                // directory events
                if event.mask.contains(EventMask::CREATE) {
                    // update watch
                    inotify.add_watch(&watch.path, WatchMask::MODIFY | WatchMask::MOVE_SELF)?;
                    watch.set_pos(0);
                }
            } else {
                // file events
                if event.mask.contains(EventMask::MOVE_SELF)
                    | event.mask.contains(EventMask::IGNORED)
                {
                } else {
                    let metadata = fs::metadata(&watch.path)?;
                    let f = File::open(&watch.path)?;
                    let mut reader = BufReader::new(f);
                    reader.seek(SeekFrom::Start(watch.pos))?;

                    loop {
                        linebuffer.clear();
                        let bytes_read = reader.read_until(b'\n', &mut linebuffer)?;
                        if bytes_read == 0 {
                            break;
                        } else {
                            if String::from_utf8_lossy(&linebuffer[..])
                                .contains(&sudo_failure.message)
                            {
                                sudo_map.add();
                                sudo_map.clean();
                                if sudo_map.auth_time.len() >= RATE_LIMIT {
                                    println!("sudo bashing detected");
                                    sudo_map.auth_time = vec![];
                                }
                            }
                            if String::from_utf8_lossy(&linebuffer[..])
                                .contains(&systemauth_failure.message)
                            {
                                system_map.add();
                                system_map.clean();
                                if system_map.auth_time.len() >= RATE_LIMIT {
                                    println!("system-auth bashing detected");
                                    system_map.auth_time = vec![];
                                }
                            }
                        }
                    }
                    watch.set_pos(metadata.len());
                }
            }
        }
    }
}
