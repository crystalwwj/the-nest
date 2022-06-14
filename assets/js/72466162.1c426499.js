"use strict";(self.webpackChunkthe_nest_new=self.webpackChunkthe_nest_new||[]).push([[337],{3905:function(e,t,n){n.d(t,{Zo:function(){return u},kt:function(){return d}});var r=n(7294);function o(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function a(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){o(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function s(e,t){if(null==e)return{};var n,r,o=function(e,t){if(null==e)return{};var n,r,o={},i=Object.keys(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||(o[n]=e[n]);return o}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}var l=r.createContext({}),c=function(e){var t=r.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):a(a({},t),e)),n},u=function(e){var t=c(e.components);return r.createElement(l.Provider,{value:t},e.children)},p={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},m=r.forwardRef((function(e,t){var n=e.components,o=e.mdxType,i=e.originalType,l=e.parentName,u=s(e,["components","mdxType","originalType","parentName"]),m=c(n),d=o,y=m["".concat(l,".").concat(d)]||m[d]||p[d]||i;return n?r.createElement(y,a(a({ref:t},u),{},{components:n})):r.createElement(y,a({ref:t},u))}));function d(e,t){var n=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var i=n.length,a=new Array(i);a[0]=m;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s.mdxType="string"==typeof e?e:o,a[1]=s;for(var c=2;c<i;c++)a[c]=n[c];return r.createElement.apply(null,a)}return r.createElement.apply(null,n)}m.displayName="MDXCreateElement"},5656:function(e,t,n){n.r(t),n.d(t,{frontMatter:function(){return s},contentTitle:function(){return l},metadata:function(){return c},toc:function(){return u},default:function(){return m}});var r=n(7462),o=n(3366),i=(n(7294),n(3905)),a=["components"],s={sidebar_position:1},l="Intro",c={unversionedId:"cybersecurity/pentest-notes/intro",id:"cybersecurity/pentest-notes/intro",title:"Intro",description:"When prepping for the OSCP, I took notes on all the boxes and pitfalls I encountered. I tried to keep them as structured and easily accessible as I could within the limited time I had, but still, it was makeshift and messy...",source:"@site/docs/cybersecurity/pentest-notes/intro.md",sourceDirName:"cybersecurity/pentest-notes",slug:"/cybersecurity/pentest-notes/intro",permalink:"/the-nest/docs/cybersecurity/pentest-notes/intro",editUrl:"https://github.com/crystalwwj/the-nest/edit/main/docs/cybersecurity/pentest-notes/intro.md",tags:[],version:"current",sidebarPosition:1,frontMatter:{sidebar_position:1},sidebar:"tutorialSidebar",previous:{title:"Deploy your site",permalink:"/the-nest/docs/tutorial-basics/deploy-your-site"},next:{title:"Host Discovery and Service Enumeration",permalink:"/the-nest/docs/cybersecurity/pentest-notes/foothold/discovery-and-enum"}},u=[],p={toc:u};function m(e){var t=e.components,n=(0,o.Z)(e,a);return(0,i.kt)("wrapper",(0,r.Z)({},p,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"intro"},"Intro"),(0,i.kt)("p",null,"When prepping for the OSCP, I took notes on all the boxes and pitfalls I encountered. I tried to keep them as structured and easily accessible as I could within the limited time I had, but still, it was makeshift and messy..."),(0,i.kt)("p",null,"This is why I'm trying to review and migrate my Bear and CherryTree notes here. Hopefully they're more organized now."),(0,i.kt)("p",null,"Special note: lots of the examples in my notes come from internet resources, such as my favorite ",(0,i.kt)("a",{parentName:"p",href:"https://book.hacktricks.xyz/"},"Hacktricks"),". It's super comprehensive and detailed, please check it out!"),(0,i.kt)("p",null,"Estimated structure:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"Foothold",(0,i.kt)("ul",{parentName:"li"},(0,i.kt)("li",{parentName:"ul"},"host discovery and service enumeration"),(0,i.kt)("li",{parentName:"ul"},"connecting and using common services"),(0,i.kt)("li",{parentName:"ul"},"web "),(0,i.kt)("li",{parentName:"ul"},"SMB, LDAP, Kerberos"),(0,i.kt)("li",{parentName:"ul"},"NFS"))),(0,i.kt)("li",{parentName:"ul"},"Privesc",(0,i.kt)("ul",{parentName:"li"},(0,i.kt)("li",{parentName:"ul"},"Linux"),(0,i.kt)("li",{parentName:"ul"},"Windows"))),(0,i.kt)("li",{parentName:"ul"},"Reverse shells and msfvenom"),(0,i.kt)("li",{parentName:"ul"},"Password cracking"),(0,i.kt)("li",{parentName:"ul"},"Exploits: searching and compiling"),(0,i.kt)("li",{parentName:"ul"},"File transfer"),(0,i.kt)("li",{parentName:"ul"},"Tunneling / port forwarding"),(0,i.kt)("li",{parentName:"ul"},"Useful commands and tips")),(0,i.kt)("p",null,"Everything WIP hahaha"))}m.isMDXComponent=!0}}]);