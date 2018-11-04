#[macro_use] extern crate clap;
extern crate regex;
extern crate ssh2;
extern crate tempfile;
extern crate username;
extern crate walkdir;

use std::fs;
use std::fs::File;
use std::io;
use std::net::TcpStream;
use std::path::Path;

use clap::{App, Arg};
use regex::Regex;
use ssh2::Session;
use tempfile::tempdir;
use walkdir::WalkDir;

#[cfg(target_family = "unix")]
use std::os::unix::fs::*;

struct RemotePath {
    hostname: String,
    username: Option<String>,
    path: String,
}

fn main() -> std::io::Result<()> {

    let re = Regex::new(r"(?x)^
      ((?P<username>[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)) # username
      @)?
      (?P<hostname>((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])) # ip address
      |
      ((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))) # hostname
      :(?P<path>.*)$
    ").unwrap();

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about("sc(ra)p - A command-line scp replacement")
        .arg(Arg::with_name("source")
             .help("Source File to be copied from")
             .required(true)
             .index(1)
        )
        .arg(Arg::with_name("destination")
             .help("Destination File to be copied to")
             .required(true)
             .index(2)
        )
        .arg(Arg::with_name("recursive")
             .short("r")
             .long("recursive")
             .help("Recursive Copy")
        )
        .get_matches();

    let source = matches.value_of("source").unwrap();
    let destination = matches.value_of("destination").unwrap();

    if source == destination {
        println!("Destination is same as the source");
        return Ok(());
    }

    let remote_source: Option<RemotePath> = if source.starts_with(".") {
        None
    } else {
        if source.contains(':') {
            re.captures(source).map(|c| RemotePath{
                username: c.name("username").map(|u| u.as_str().into()),
                hostname: c.name("hostname").unwrap().as_str().into(),
                path: c.name("path").unwrap().as_str().into(),
            })
        } else {
            None
        }
    };

    let remote_dest: Option<RemotePath> = if destination.starts_with(".") {
        None
    } else {
        if destination.contains(':') {
            re.captures(destination).map(|c| RemotePath{
                username: c.name("username").map(|u| u.as_str().into()),
                hostname: c.name("hostname").unwrap().as_str().into(),
                path: c.name("path").unwrap().as_str().into(),
            })
        } else {
            None
        }
    };

    let recursive = matches.is_present("recursive");
    match (remote_source, remote_dest) {
        (None, None) => copy_local_local(source, destination, recursive),
        (Some(rs), None) => copy_remote_local(rs, destination, recursive),
        (None, Some(rd)) => copy_local_remote(source, rd, recursive),
        (Some(rs), Some(rd)) => {
            let dir = tempdir()?;
            let file_path = dir.path().join("my-temp");
            copy_remote_local(rs, file_path, recursive)?;
            let file_path = dir.path().join("my-temp");
            copy_local_remote(file_path, rd, recursive)
        },
    }

}

fn copy_remote_local<P: AsRef<Path>>(source: RemotePath, destination: P, recursive: bool) -> std::io::Result<()> {
    if recursive {
        println!("Recursive copy for remote connections is not supported right now");
        return Ok(());
    }
    let username = match source.username {
        None => username::get_user_name().ok(),
        Some(x) => Some(x)
    };
    if username.is_none() {
        println!("please specify username for ssh session");
        return Ok(());
    }
    let username = username.unwrap();
    // Connect to the local SSH server
    let tcp = TcpStream::connect(format!("{}:22", source.hostname))?;
    let mut sess = Session::new().unwrap();
    match sess.handshake(&tcp) {
        Err(_) => {
            println!("Error in session tcp handshake");
            return Ok(());
        },
        Ok(_) => ()
    }
    match sess.userauth_agent(&username) {
        Err(_) => {
            println!("Error in session userauth agent");
            return Ok(());
        },
        Ok(_) => ()
    };

    let destination: &Path = destination.as_ref();
    let source_path: &Path = source.path.as_ref();
    let alt_dest = destination.join(source_path.file_name().unwrap());
    let norm_dest = if destination.exists() && destination.is_dir() {
        alt_dest.as_ref()
    } else {
        for parent in destination.parent().into_iter() {
            fs::create_dir_all(parent)?;
        }
        destination
    };

    let (mut remote_file, stat) = sess.scp_recv(source.path.as_ref()).unwrap();
    let mut dest_file = File::create(norm_dest)?;
    io::copy(&mut remote_file, &mut dest_file)?;
    println!("Copied: {} bytes", stat.size());
    Ok(())
}

fn copy_local_remote<P: AsRef<Path>>(source: P, destination: RemotePath, recursive: bool) -> std::io::Result<()> {
    if recursive {
        println!("Recursive copy for remote connections is not supported right now");
        return Ok(());
    }
    let username = match destination.username {
        None => username::get_user_name().ok(),
        Some(x) => Some(x)
    };
    if username.is_none() {
        println!("please specify username for ssh session");
        return Ok(());
    }
    let username = username.unwrap();
    // Connect to the local SSH server
    let tcp = TcpStream::connect(format!("{}:22", destination.hostname))?;
    let mut sess = Session::new().unwrap();
    match sess.handshake(&tcp) {
        Err(_) => {
            println!("Error in session tcp handshake");
            return Ok(());
        },
        Ok(_) => ()
    }
    match sess.userauth_agent(&username) {
        Err(_) => {
            println!("Error in session userauth agent");
            return Ok(());
        },
        Ok(_) => ()
    };

    let source: &Path = source.as_ref();
    if !source.exists() {
        println!("'{}' - does not exist", source.display());
        return Ok(());
    }
    if source.is_dir() {
        println!("{} -r not specified; omitting directory '{}'", crate_name!(), source.display());
        return Ok(())
    }
    if source.is_file() {
        let mut f = File::open("foo.txt")?;
        let metadata = f.metadata()?;
        let mut remote_file = sess.scp_send(destination.path.as_ref(), metadata.permissions().mode() as i32, metadata.len(), None).unwrap();
        io::copy(&mut f, &mut remote_file)?;
    } else {
        println!("symlink has no meaning over ssh connections");
    }
    Ok(())
}

fn copy_local_local<P: AsRef<Path>, Q: AsRef<Path>>(source: P, destination: Q, recursive: bool) -> std::io::Result<()> {
    let source: &Path = source.as_ref();
    let destination: &Path = destination.as_ref();

    if !source.exists() {
        println!("'{}' - does not exist", source.display());
        return Ok(());
    }

    if recursive && source.is_dir() {
        fs::create_dir_all(destination)?;
        for entry in WalkDir::new(source)
            .into_iter()
            .filter_map(|e| e.ok()) {
                let path = entry.path();
                let rel_path = path.strip_prefix(source).unwrap_or(path);
                let s = path;
                let d = destination.join(rel_path);
                if entry.file_type().is_dir() {
                    fs::create_dir_all(d)?;
                } else {
                    for parent in d.parent().into_iter() {
                        fs::create_dir_all(parent)?;
                    }
                    if entry.file_type().is_file() {
                        fs::copy(s, d)?;
                    } else if entry.path_is_symlink() {
                        let target_path = fs::read_link(entry.path())?;
                        create_symlink(target_path, d)?;
                    }
                }
            }
    } else {
        if source.is_dir() {
            println!("{} -r not specified; omitting directory '{}'", crate_name!(), source.display());
            return Ok(())
        }
        let alt_dest = destination.join(source.file_name().unwrap());
        let norm_dest = if destination.exists() && destination.is_dir() {
            alt_dest.as_ref()
        } else {
            for parent in destination.parent().into_iter() {
                fs::create_dir_all(parent)?;
            }
            destination
        };
        if source.is_file() {
            fs::copy(source, norm_dest)?;
        } else {
            let target_path = fs::read_link(source)?;
            create_symlink(target_path, norm_dest)?;
        }
    }
    Ok(())
}

#[cfg(target_family = "windows")]
fn create_symlink<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> std::io::Result<()> {
    if src.is_dir() {
        std::os::windows::fs::symlink_dir(src, dst)
    } else {
        std::os::windows::fs::symlink_file(src, dst)
    }
}

#[cfg(target_family = "unix")]
fn create_symlink<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> std::io::Result<()> {
    std::os::unix::fs::symlink(src, dst)
}
