# Usage Instructions

## Running the Group Server

To start the Group Server:
 - Enter the directory containing `RunGroupServer.class`
 - Type `java RunGroupServer [port number]`

Note that the port number argument to `RunGroupServer` is optional.  This argument specifies the port that the Group Server will listen to.  If unspecified, it defaults to port 8765.

When the group server is first started, there are no users or groups. Since there must be an administer of the system, the user is prompted via the console to enter a username. This name becomes the first user and is a member of the *ADMIN* group.  No groups other than *ADMIN* will exist.

## Running the File Server

To start the File Server:
 - Enter the directory containing `RunFileServer.class`
 - Type `java RunFileServer [port number]`

Note that the port number argument to `RunFileServer` is optional.  This argument speficies the port that the File Server will list to. If unspecified, it defaults to port 4321.

The file server will create a shared_files inside the working directory if one does not exist. The file server is now online.

## Running the Application (Kubera)

`java Kubera -u [username]`

## Resetting the Group or File Server

To reset the Group Server, delete the files `UserList.bin`, `ALPHA.keypair`, and `ALPHA.pub`

To reset the File Server, delete the `FileList.bin` and `FilePile.keypair` files, and delete the `shared_files/` directory.

To reset the trusted File Servers, remove all files ending with `-TrustedServers.bin`.
