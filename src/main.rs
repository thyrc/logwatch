use std::io;

use futures_util::StreamExt;
use inotify::{EventMask, Inotify, WatchMask};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant};

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
}

struct AuthFailure {
    kind: Auth,
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let mut watch = Watched::new("/tmp/auth.log");

    if watch.path.is_file() {
        let meta = fs::metadata(&watch.path)?;
        watch.set_pos(meta.len());
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

    let mut inotify = Inotify::init().expect("Failed to initialize inotify");

    inotify.add_watch(
        &watch.dir,
        WatchMask::CREATE | WatchMask::MODIFY | WatchMask::MOVED_FROM,
    )?;

    let mut buffer = [0; 32];
    let mut stream = inotify.event_stream(&mut buffer)?;

    while let Some(event_or_error) = stream.next().await {
        if let Ok(event) = event_or_error {
            if Some(OsString::from(watch.file)) == event.name {
                if event.mask.contains(EventMask::CREATE)
                    || event.mask.contains(EventMask::MOVED_FROM)
                {
                    watch.set_pos(0);
                } else {
                    // println!("event: {:?}", event);
                    let metadata = fs::metadata(&watch.path)?;
                    let f = File::open(&watch.path)?;
                    let mut reader = BufReader::new(f);
                    let _pos = reader.seek(SeekFrom::Start(watch.pos))?;
                    for line in reader.lines() {
                        if let Ok(l) = line {
                            if l.contains(&sudo_failure.message) {
                                sudo_map.add();
                                if sudo_map.auth_time.len() >= 3 {
                                    println!("sudo bashing detected");
                                }
                            }
                            if l.contains(&systemauth_failure.message) {
                                system_map.add();
                                if system_map.auth_time.len() >= 3 {
                                    println!("system-auth bashing detected");
                                }
                            }
                        }
                    }
                    watch.set_pos(metadata.len());
                }

                // clean-up
                sudo_map.auth_time = sudo_map
                    .auth_time
                    .into_iter()
                    .filter(|x| x.elapsed() <= Duration::from_secs(300))
                    .collect::<Vec<_>>();

                system_map.auth_time = system_map
                    .auth_time
                    .into_iter()
                    .filter(|x| x.elapsed() <= Duration::from_secs(300))
                    .collect::<Vec<_>>();
            }
        }
    }

    Ok(())
}
