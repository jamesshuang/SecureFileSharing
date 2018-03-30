# CS 1653 Term Project, Phase 1

Nathaniel Blake \< nsb23@pitt.edu \>

James Huang \< jah245@pitt.edu \>

## Security Properties

 * __Property 1: User Authentication.__ A user *u* shall prove her identity to both the Group Server and the File Server before any other system interaction in such a way that no other user *u'* is able to operate with the individual and group permissions assigned to *u*. Without this requirement, users could pretend to be other users in order to access files for which they do not have access permission.
 * __Property 2: Server Authentication.__ A Group or File Server *S* shall prove its legitimacy to any connecting user before prompting the user for authentication information. This requirement ensures that servers outside this system cannot pretend to be a Group or File Server in order to gain user authentication information.
 * __Property 3: Permission-based Access.__ All access to the system and any uploaded files shall be denied unless a user has explicit permission via user or group assignment. Defaulting to denial follows the recommendation of Saltzer and Schroeder [1] to use "fail-safe defaults," which prevent edge-case failures that result in improperly allowing or restricting access.
 * __Property 4: Group Server Availability.__ The Group Server *S<sub>G</sub>* shall be designed with maximum availability as a primary goal. Since every user is first required to authenticate via the Group Server, a lack of availability of *S<sub>G</sub>* would prevent users from using other portions of the system, even if those other components are available.
 * __Property 5: File Server Availability.__ File Servers shall be designed and deployed such that at least one File Server *S<sub>i</sub>* is available to serve the requests of an authorized user. This requirement ensures that properly authorized and authenticated users are not prevented from accessing files to which they have access.
 * __Property 6: File Server Consistency.__ When a user uploads, deletes, or modifies a file *f* on a particular File Server *S<sub>i</sub>*, the changes in *f* should be propagated as quickly as possible to all other File Servers *S<sub>1</sub>, ..., S<sub>n</sub>*. In particular, this ensures that a file deleted from *S<sub>i</sub>* cannot then be accessed on *S<sub>j</sub>*. Further, this ensures the integrity of changes made to *f* on *S<sub>i</sub>*, so that stale versions do not remain on any other server *S<sub>j</sub>*.
 * __Property 7: File Access and Modification Permissions.__ The system shall provide explicit, separate permissions for file access and file modification, on a per-file basis, and with both user- and group-based granularity. Without this property, permission controls would not be fine-grained enough to provide, for instance, read-only access to a file to users in a given group.
 * __Property 8: File Ownership.__ Each file *f* in the system shall have exactly one user as its owner. The owner of *f* shall hold irrevocable access and modification permissions for *f*. Moreover, the owner of *f* is the only user who is permitted to remove *f* from the system, change the owner of *f*, or change the users or groups with which *f* is shared. This property ensures that files do not get deleted by users meant only to have read or modification access to the file. This assumes that users with modification access will not purposefully delete the file contents, in effect overriding the owner's exclusive delete permission. Without this property, a user with whom the file is shared could share it with additional groups, thus circumventing the limitations of group-based sharing.
 * __Property 9: Administrative User Operations.__ Only administrative users shall be permitted to create or delete users within the system. Without this property, an adversary could create or delete users, which would potentially affect other users' ability to use the system. This assumes we have one or more trusted administrative users. This property follows the advice in [1] to grant "least privilege."
 * __Property 10: Administrative Group Operations.__ Only administrative users shall be permitted to create or delete groups within the system. Without this property, an adversary could create or delete users, which would potentially affect trusted users' ability to use the system. This assumes we have one or more trusted administrative users. This property follows the advice in [1] to grant "least privilege."
 * __Property 11: Session-based Authentication.__ Authentication shall be granted to users on a per-session basis. Without this property, a user could maintain authentication indefinitely; from a defense perspective, an adversary could gain access to a user's stale authentication. This assumes authentication can be revoked.
 * __Property 12: Confidential Transmission.__ The content of communications between Clients and File or Group Servers should remain confidential, in order to prevent eavesdropping from outside parties. This assumes that the existence of transmission between Client and Server does not need to be hidden.
 * __Property 13: File Transmission Integrity.__ Any modifications or corruptions of data being transmitted between a Client and Server of the system should be detected and corrected. This protects against malicious and accidental modification from an outside party during transmission of file. This assumes that we have a mechanism to detect change.
 * __Property 14: Group Administration Permissions.__ For each group *g*, there shall be zero or more members of *g* who have permission to add and remove users from *g*. These "group administrators" do not need to have other administrative permissions. This allows for group-level administrators who have minimal permission to modify other parts of the system.
 * __Property 15: Domain-based Access Restriction.__ Users outside a given domain shall not have access to the application. This property allows a deployment of the application to be "locked down" to the deployment domain, physical or otherwise. This assumes the ability to identify the origin of user actions.
 * __Property 16: Multiple-Party Authorization.__ The system shall allow for authorization that requires the participation of multiple parties. This property follows the suggestion in [1] for "separation of privilege." This allows for protection against untrusted individual administrative users, for instance.
 * __Property 17: User Confidentiality.__ According to user or administrator configuration, the system shall keep confidential all user information up to and possibly including the existence of a user account, except to administrative users and other users in the same group(s).
 * __Property 18: Group Confidentiality.__ According to administrator configuration, for every group *g*, the existence of *g* and the list of members in *g* shall be kept confidential except from administrative users and members of *g*. Without this property, the system could not accommodate confidential groups.
 * __Property 19: Server Storage Confidentiality.__ Any contents stored on the Group Server or any File Server related to the application configuration or user data should be confidential except to an authenticated and authorized administrative user. This includes shared files themselves. Without this property, physical access to a File Server would allow unrestricted access to all of its contents.

## Threat Models

### Offline Home File-share

The application can be deployed to any offline site (not connected to the Internet). This type of deployment can be achieved offline if transmission is done through a router. Only users connected to the offline network will be allowed to use the system. There is not remote access to the system. Since this deployment is offline, we do not have to worry about malicious activity from outside parties. This environment will typically contain a limited number of users, like a family home. All users in this environment will usually know each other. Users will still only be allowed to view files that they have access to. Groups are allowed, however it will not be common since there is only a small number of users in a system like this. 

Since this type of deployment will be used by a small number of users who know and trust each other, it is safe to assume that the users of the system will not try to do anything malicious to other users' files. This deployment also assumes that users will not add any malicious files to the system. However, users will not be trusted to delete all files to which they have access -- only the owner of the file will be allowed that privilege. There will only be one administrator for this system who will create and delete users. This system also trusts that users will not try to eavesdrop or modify transmissions over the router, so confidentiality is less important. Last, this deployment trusts that users will not try to gain unauthorized access to another user's account by using stale authentication tokens, so session-based authentication is unnecessary (i.e., once a user logs in, they stay logged in, unless they explicitly sign out).

The following Security Properties from above apply to this threat model:
* Property 1: User Authentication - Users on the system will have to log in to use their account. The administrator needs to be authenticated so they can add or remove users. File owners also need to be authenticated so they can delete files.
* Property 3: Permission-Based Access - Ensures that users can only view files that they have access to.
* Property 4: Group Server Availability - Users on the system will always have access to the group server so they can log in.
* Property 5: File Server Availability - Users on the system should have access to the file server as much as possible so they can perform file operations, although downtime is not detrimental.
* Property 7: File Access and Modification Permissions - Ensures that only users with permission can perform operations on a file.
* Property 8: File Ownership - Ensures that only the owner of a file can delete it or give someone permission to view the file.
* Property 9: Administrative User Operations - Ensures that users can be created or deleted from the system.
* Property 10: Administrative Group Operations - Ensures that groups can be created or deleted from the system.
* Property 14: Group Administration Permissions - Ensures that users can be added or removed from groups. The administrator who creates the group decides the user who has group membership control.
* Property 15: Domain-based Access Restriction - Only users that are connected to the offline network will be allowed to use the system, although this is not enforced by application but rather by the network configuration.

### Business File Repository with Employee Remote Access

This deployment of the group-based file sharing application would serve a large corporation's enterprise needs of synchronizing work among various groups of employees. Primary access to the system would take place from within the office sub-network, but for convenience, employees would also be permitted to set up a remote access mechanism. Moreover, given multiple offices for the same business, file servers would need to be distributed to allow quick access from any office location.

While employees should generally be trusted not to attempt malicious modifications of others' files, the system should still assume the possibility of user negligence that has the potential to be destructive. Administrators of individual groups should be trusted, technically skilled members of their respective departments within the business, such that each group administrator has control only over the membership of those in that group. Last, there should be two highly trusted lead system administrators.

The following Security Properties from above apply to this threat model:
* Property 1: User authentication provides the foundation for group-based file-sharing, so that users in each department are assigned to different groups with different sets of shared files.
* Property 2: Server Authentication in this context prevents adversaries outside the company from impersonating nodes in the system to steal employee credentials or other sensitive data.
* Property 3: Fail-safe defaults ensure that each employee can access exclusively those files which have been shared with the employee or a group to which the employee belongs.
* Property 4: Authentication is a necessary step for using the system, so failure of the Group Server could prevent employees from accessing files important to getting work done, resulting in wasted time and money.
* Property 5: As above, if employees cannot quickly access their shared files, they will be unable to complete useful work on shared projects.
* Property 6: File consistency is essential across departments and office buildings to ensure that all work is being synchronized among employees.
* Property 7: A fine-grained set of permissions is necessary to separate employee tasks; for instance, employees might need to view a department superior's schedule for practical reasons but should not be able to add or change appointments.
* Property 8: File ownership allows employees to share their documents as they wish with members of their groups, as well as to be assured that files they share will not be deleted by accident without their knowledge.
* Properties 9 & 10: The company deploying the application will want centralized administration, including the creation and deletion of users and groups.
* Property 11: The company will not want employee sign-ins to remain valid indefinitely. Consider an employee who signs in remotely from a shared computer at home; if her session remains valid, a child or spouse could potentially access her confidential work documents.
* Property 12: Especially for remote access, but also within the office walls, the contents of documents and user actions should not be visible except to the application and the user.
* Property 13: Any outside tampering of files during transmission could cause a breach of confidentiality or other security properties if not properly detected. Moreover, invalid contents in a file, even by transmission error, could disrupt business interests.
* Property 14: Each department of the company will likely want a technical lead who can add/remove employees within that department from relevant file shares, without having to get central administrators involved.
* Property 15: The company could restrict access entirely to its office sub-net, or, given the desire for remote access, enforce a policy of approving which personal devices may connect to the application remotely.
* Property 16: Requiring multiple parties for certain administrative tasks could prevent sabotage by a single malicious system administrator. For instance, deleting a group and all its files (for the closing of a department within the company) could require the authorization of two administrators.
* Properties 17 & 18: For secretive working groups within a company, it may be important to hide the existence of groups and especially details concerning members, where even loosely-coupled data could compromise confidentiality.
* Property 19: Encrypting or otherwise protecting the data on the physical server storage will mitigate the risk of physical breaches of security, for instance by an adversary who manages to steal a File Server hard disk drive.

### Tech-Savvy Personal File Store

A technically inclined individual may want to utilize the application with a minimal configuration in order to make a personal document, music, photo, or other media library accessible from outside the house. In this instance, very few of the integrity-related properties hold importance: the user is unconcerned with slightly corrupted media downloads, and thinks this personal share to be an unlikely target for an attacker. Moreover, since it's one user managing the application primarily for personal use (with a few additional accounts for friends, family members, and/or colleagues, on occasion), the strict access controls can largely be relaxed.

The following Security Properties from above apply to this threat model:
* Property 1: Without authentication, anyone who gets the address of this user's share would be able to access everything. Moreover, this user does still want to share different files with different friends and other users.
* Property 3: Although the user plans to use the file store essentially as a "Public" folder behind a log-in, without this property all other users could access everything.
* Properties 7 & 8: All users other than the primary one will get read-only access, and the main user will be owner of all files.
* Properties 9 & 10: The primary user will want to be able to add accounts for friends and others as well as to manage groupings thereof; this is the central function of a group-based file sharing system.
* Property 12: Despite the minimal security concerns of the primary user, semi-personal documents should not be easily accessible to eavesdroppers, nor should log-in credentials.

## References

 * [1] Jerome H. Saltzer and Michael D. Schroeder, The Protection of Information in Computer Systems, Proceedings of the IEEE 63(9): 1278-1308, Sep. 1975.
