use serde::{Serialize,Deserialize};
use std::collections::HashMap;
use std::time::SystemTime;


pub type Inode= u64;

#[derive(Serialize,Deserialize,Debug,Clone)]
pub struct FileAttributes{
    pub inode: Inode,
    pub size: u64,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,

    pub content_blob_id:String,
}

#[derive(Serialize,Deserialize,Debug,Clone)]
pub struct DirectoryEntry{
    pub name:String,
    pub inode:Inode,
}

#[derive(Serialize,Deserialize,Default,Debug)]
pub struct MetadataManager{
    pub inodes: HashMap<Inode,FileAttributes>,

    pub directory_children:HashMap<Inode,Vec<DirectoryEntry>>,

    next_inode:Inode,
}

impl MetadataManager{

    pub fn new()->Self{
        let mut manager=MetadataManager{
            inodes:HashMap::new(),
            directory_children:HashMap::new(),
            next_inode:2,
        };

        let now=SystemTime::now();
        let root_attrs= FileAttributes{
            inode:1,
            size:0,
            atime:now,mtime:now,ctime:now,
            perm:0o755,
            nlink:2,
            uid:1000,
            gid:1000,
            content_blob_id:String::new(),
        };

        manager.inodes.insert(1, root_attrs);
        manager.directory_children.insert(1, Vec::new());

        manager
    }
}