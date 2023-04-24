"use strict";(self.webpackChunkcosmos_sdk_docs=self.webpackChunkcosmos_sdk_docs||[]).push([[5589],{3905:(e,r,t)=>{t.d(r,{Zo:()=>d,kt:()=>m});var o=t(7294);function n(e,r,t){return r in e?Object.defineProperty(e,r,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[r]=t,e}function i(e,r){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);r&&(o=o.filter((function(r){return Object.getOwnPropertyDescriptor(e,r).enumerable}))),t.push.apply(t,o)}return t}function a(e){for(var r=1;r<arguments.length;r++){var t=null!=arguments[r]?arguments[r]:{};r%2?i(Object(t),!0).forEach((function(r){n(e,r,t[r])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):i(Object(t)).forEach((function(r){Object.defineProperty(e,r,Object.getOwnPropertyDescriptor(t,r))}))}return e}function s(e,r){if(null==e)return{};var t,o,n=function(e,r){if(null==e)return{};var t,o,n={},i=Object.keys(e);for(o=0;o<i.length;o++)t=i[o],r.indexOf(t)>=0||(n[t]=e[t]);return n}(e,r);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(o=0;o<i.length;o++)t=i[o],r.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(n[t]=e[t])}return n}var l=o.createContext({}),p=function(e){var r=o.useContext(l),t=r;return e&&(t="function"==typeof e?e(r):a(a({},r),e)),t},d=function(e){var r=p(e.components);return o.createElement(l.Provider,{value:r},e.children)},c={inlineCode:"code",wrapper:function(e){var r=e.children;return o.createElement(o.Fragment,{},r)}},u=o.forwardRef((function(e,r){var t=e.components,n=e.mdxType,i=e.originalType,l=e.parentName,d=s(e,["components","mdxType","originalType","parentName"]),u=p(t),m=n,g=u["".concat(l,".").concat(m)]||u[m]||c[m]||i;return t?o.createElement(g,a(a({ref:r},d),{},{components:t})):o.createElement(g,a({ref:r},d))}));function m(e,r){var t=arguments,n=r&&r.mdxType;if("string"==typeof e||n){var i=t.length,a=new Array(i);a[0]=u;var s={};for(var l in r)hasOwnProperty.call(r,l)&&(s[l]=r[l]);s.originalType=e,s.mdxType="string"==typeof e?e:n,a[1]=s;for(var p=2;p<i;p++)a[p]=t[p];return o.createElement.apply(null,a)}return o.createElement.apply(null,t)}u.displayName="MDXCreateElement"},2770:(e,r,t)=>{t.r(r),t.d(r,{assets:()=>l,contentTitle:()=>a,default:()=>c,frontMatter:()=>i,metadata:()=>s,toc:()=>p});var o=t(7462),n=(t(7294),t(3905));const i={sidebar_position:1},a="Errors",s={unversionedId:"building-modules/errors",id:"version-v0.47/building-modules/errors",title:"Errors",description:"This document outlines the recommended usage and APIs for error handling in Cosmos SDK modules.",source:"@site/versioned_docs/version-v0.47/building-modules/12-errors.md",sourceDirName:"building-modules",slug:"/building-modules/errors",permalink:"/v0.47/building-modules/errors",draft:!1,tags:[],version:"v0.47",sidebarPosition:1,frontMatter:{sidebar_position:1},sidebar:"tutorialSidebar",previous:{title:"Recommended Folder Structure",permalink:"/v0.47/building-modules/structure"},next:{title:"Upgrading Modules",permalink:"/v0.47/building-modules/upgrade"}},l={},p=[{value:"Registration",id:"registration",level:2},{value:"Wrapping",id:"wrapping",level:2},{value:"ABCI",id:"abci",level:2}],d={toc:p};function c(e){let{components:r,...t}=e;return(0,n.kt)("wrapper",(0,o.Z)({},d,t,{components:r,mdxType:"MDXLayout"}),(0,n.kt)("h1",{id:"errors"},"Errors"),(0,n.kt)("admonition",{title:"Synopsis",type:"note"},(0,n.kt)("p",{parentName:"admonition"},"This document outlines the recommended usage and APIs for error handling in Cosmos SDK modules.")),(0,n.kt)("p",null,"Modules are encouraged to define and register their own errors to provide better\ncontext on failed message or handler execution. Typically, these errors should be\ncommon or general errors which can be further wrapped to provide additional specific\nexecution context."),(0,n.kt)("h2",{id:"registration"},"Registration"),(0,n.kt)("p",null,"Modules should define and register their custom errors in ",(0,n.kt)("inlineCode",{parentName:"p"},"x/{module}/errors.go"),".\nRegistration of errors is handled via the ",(0,n.kt)("a",{parentName:"p",href:"https://github.com/cosmos/cosmos-sdk/blob/main/errors/errors.go"},(0,n.kt)("inlineCode",{parentName:"a"},"errors")," package"),"."),(0,n.kt)("p",null,"Example:"),(0,n.kt)("pre",null,(0,n.kt)("code",{parentName:"pre",className:"language-go",metastring:"reference",reference:!0},"https://github.com/cosmos/cosmos-sdk/blob/v0.47.0-rc1/x/distribution/types/errors.go#L1-L21\n")),(0,n.kt)("p",null,'Each custom module error must provide the codespace, which is typically the module name\n(e.g. "distribution") and is unique per module, and a uint32 code. Together, the codespace and code\nprovide a globally unique Cosmos SDK error. Typically, the code is monotonically increasing but does not\nnecessarily have to be. The only restrictions on error codes are the following:'),(0,n.kt)("ul",null,(0,n.kt)("li",{parentName:"ul"},"Must be greater than one, as a code value of one is reserved for internal errors."),(0,n.kt)("li",{parentName:"ul"},"Must be unique within the module.")),(0,n.kt)("p",null,"Note, the Cosmos SDK provides a core set of ",(0,n.kt)("em",{parentName:"p"},"common")," errors. These errors are defined in ",(0,n.kt)("a",{parentName:"p",href:"https://github.com/cosmos/cosmos-sdk/blob/main/types/errors/errors.go"},(0,n.kt)("inlineCode",{parentName:"a"},"types/errors/errors.go")),"."),(0,n.kt)("h2",{id:"wrapping"},"Wrapping"),(0,n.kt)("p",null,"The custom module errors can be returned as their concrete type as they already fulfill the ",(0,n.kt)("inlineCode",{parentName:"p"},"error"),"\ninterface. However, module errors can be wrapped to provide further context and meaning to failed\nexecution."),(0,n.kt)("p",null,"Example:"),(0,n.kt)("pre",null,(0,n.kt)("code",{parentName:"pre",className:"language-go",metastring:"reference",reference:!0},"https://github.com/cosmos/cosmos-sdk/blob/v0.47.0-rc1/x/bank/keeper/keeper.go#L141-L182\n")),(0,n.kt)("p",null,"Regardless if an error is wrapped or not, the Cosmos SDK's ",(0,n.kt)("inlineCode",{parentName:"p"},"errors")," package provides a function to determine if\nan error is of a particular kind via ",(0,n.kt)("inlineCode",{parentName:"p"},"Is"),"."),(0,n.kt)("h2",{id:"abci"},"ABCI"),(0,n.kt)("p",null,"If a module error is registered, the Cosmos SDK ",(0,n.kt)("inlineCode",{parentName:"p"},"errors")," package allows ABCI information to be extracted\nthrough the ",(0,n.kt)("inlineCode",{parentName:"p"},"ABCIInfo")," function. The package also provides ",(0,n.kt)("inlineCode",{parentName:"p"},"ResponseCheckTx")," and ",(0,n.kt)("inlineCode",{parentName:"p"},"ResponseDeliverTx")," as\nauxiliary functions to automatically get ",(0,n.kt)("inlineCode",{parentName:"p"},"CheckTx")," and ",(0,n.kt)("inlineCode",{parentName:"p"},"DeliverTx")," responses from an error."))}c.isMDXComponent=!0}}]);