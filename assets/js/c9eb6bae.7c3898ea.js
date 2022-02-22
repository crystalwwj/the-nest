"use strict";(self.webpackChunkthe_nest_new=self.webpackChunkthe_nest_new||[]).push([[613],{3905:function(e,t,r){r.d(t,{Zo:function(){return l},kt:function(){return y}});var n=r(7294);function o(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function a(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function i(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?a(Object(r),!0).forEach((function(t){o(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function c(e,t){if(null==e)return{};var r,n,o=function(e,t){if(null==e)return{};var r,n,o={},a=Object.keys(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var s=n.createContext({}),u=function(e){var t=n.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):i(i({},t),e)),r},l=function(e){var t=u(e.components);return n.createElement(s.Provider,{value:t},e.children)},m={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},p=n.forwardRef((function(e,t){var r=e.components,o=e.mdxType,a=e.originalType,s=e.parentName,l=c(e,["components","mdxType","originalType","parentName"]),p=u(r),y=o,d=p["".concat(s,".").concat(y)]||p[y]||m[y]||a;return r?n.createElement(d,i(i({ref:t},l),{},{components:r})):n.createElement(d,i({ref:t},l))}));function y(e,t){var r=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var a=r.length,i=new Array(a);i[0]=p;var c={};for(var s in t)hasOwnProperty.call(t,s)&&(c[s]=t[s]);c.originalType=e,c.mdxType="string"==typeof e?e:o,i[1]=c;for(var u=2;u<a;u++)i[u]=r[u];return n.createElement.apply(null,i)}return n.createElement.apply(null,r)}p.displayName="MDXCreateElement"},2621:function(e,t,r){r.r(t),r.d(t,{frontMatter:function(){return c},contentTitle:function(){return s},metadata:function(){return u},toc:function(){return l},default:function(){return p}});var n=r(7462),o=r(3366),a=(r(7294),r(3905)),i=["components"],c={sidebar_position:3},s="Memory Allocation",u={unversionedId:"cybersecurity/random-notes/mem-alloc",id:"cybersecurity/random-notes/mem-alloc",title:"Memory Allocation",description:"I was reading through some binary exploit writeups from the GitHub Security Team, mainly Getting root on Ubuntu through wishful thinking, and got really interested in how memory was managed across threads and processes.",source:"@site/docs/cybersecurity/random-notes/mem-alloc.md",sourceDirName:"cybersecurity/random-notes",slug:"/cybersecurity/random-notes/mem-alloc",permalink:"/the-nest/docs/cybersecurity/random-notes/mem-alloc",editUrl:"https://github.com/crystalwwj/the-nest/edit/main/docs/cybersecurity/random-notes/mem-alloc.md",tags:[],version:"current",sidebarPosition:3,frontMatter:{sidebar_position:3},sidebar:"tutorialSidebar",previous:{title:"Summary",permalink:"/the-nest/docs/cybersecurity/random-notes/summary"}},l=[],m={toc:l};function p(e){var t=e.components,r=(0,o.Z)(e,i);return(0,a.kt)("wrapper",(0,n.Z)({},m,r,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("h1",{id:"memory-allocation"},"Memory Allocation"),(0,a.kt)("p",null,"I was reading through some binary exploit writeups from the GitHub Security Team, mainly ",(0,a.kt)("a",{parentName:"p",href:"https://securitylab.github.com/research/ubuntu-accountsservice-CVE-2021-3939/"},"Getting root on Ubuntu through wishful thinking"),", and got really interested in how memory was managed across threads and processes. "),(0,a.kt)("p",null,"I wanted answers on:"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},"memory structure and allocation during multi-threading, multi-processing, and parent/child processes"),(0,a.kt)("li",{parentName:"ul"},"how to transfer memory, e.g. malloc-ed chunks, across threads/processes"),(0,a.kt)("li",{parentName:"ul"},"other characteristics or tips when exploiting in such situations")))}p.isMDXComponent=!0}}]);