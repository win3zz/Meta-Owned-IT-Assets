# Interesting IT Assets Owned by Meta (Facebook)
Meta Platforms, Inc., formerly known as Facebook, Inc., is a highly valuable company and a significant player in the bug bounty domain. According to an [article](https://about.fb.com/news/2022/12/metas-bug-bounty-program-2022/), Meta has paid out over $16 million in bug bounties since 2011. Due to its popularity and reputation, Meta has become a prime target for security researchers and bug bounty hunters. As a result, it has become quite challenging to find even relatively simple bugs mentioned in standard security frameworks such as OWASP.

Based on my experience and analysis over the past decade, I have observed that most of the bugs rewarded by Facebook are client-side or business logic vulnerabilities. These include **MFA bypass, IDOR via GraphQL, CSRF, DOM XSS, CSP bypass, open redirect, privacy issues, rate limiting, logic flaws, authorization flaws, OAuth/SSO misconfigurations, and information disclosure**, among others. However, server-side high/critical vulnerabilities such as **SQL/LDAP/XPath/XML injection, ELI, SSTI, code/OS command injection, insecure deserialization, file path traversal (LFI/AFR/RFI), SSRF, SSI, buffer overflow/memory leak, SMTP/HTTP header injection (also known as "CRLF"), directory listing, or missing error handling leading to source code/secret leaks** are rarely found. The credit goes to Facebook's strong core architecture and secure logic implementation using the [Hack language](https://hacklang.org/) on top of the [HHVM server](https://hhvm.com/). As a result, it is nearly impossible to obtain a reverse or bind root shell of the facebook.com server.

Similar to other companies, Facebook does not rely solely on in-house developed software/applications. It also uses third-party applications and hosts them on some subdomains. As these third-party software applications require different server configurations, it is possible for server-side vulnerabilities to arise. The question then becomes: How do we identify such subdomains and find these vulnerabilities? The answer lies in reconnaissance (recon).

The term "recon" originates from its military usage to describe an information-gathering mission. Reconnaissance can be both fun and time-consuming. Therefore, I would like to share a list of interesting IT assets owned by Meta (formerly Facebook) with the security research community. I have identified all these assets using various tools and platforms, including:

- [Shodan](https://www.shodan.io/): An internet-connected device search engine.
- [Hurricane Electric BGP Toolkit](https://bgp.he.net/): A network information and IP address lookup tool.
- [DNSDumpster](https://dnsdumpster.com/): A DNS (Domain Name System) information gathering tool.
- [Censys](https://search.censys.io/): An internet-wide search engine for discovering devices and networks.
- [BinaryEdge](https://www.binaryedge.io/): An internet scanning and threat intelligence platform.
- [crt.sh](https://crt.sh/): A certificate search and monitoring tool.
- [SubdomainFinder](https://subdomainfinder.c99.nl/): A subdomain enumeration and discovery tool.
- [YouGetSignal](https://www.yougetsignal.com/tools/web-sites-on-web-server/): A web server hosting multiple websites detection tool.
- [Google Dork](https://en.wikipedia.org/wiki/Google_hacking): Customized search queries using Google's search operators.
- Other open-source programs/tools/frameworks for IT asset discovery.

This comprehensive list includes relevant details such as the applications running on these assets. For proprietary applications, information about the developer is provided, while open-source applications include links to their source code. These assets were identified during my security research, and I believe that sharing them will save time for testers in discovering subdomains and identifying the software in use.

It is important to note that **I am not promoting or encouraging anyone to access or test any of the listed assets without proper authorization. Maintain ethical practices and follow authorized access when conducting any security research. Before accessing or testing any of the assets mentioned, please read and comply with the terms, rules, and research scope specified on https://www.facebook.com/whitehat and https://www.facebook.com/security/advisories/Vulnerability-Disclosure-Policy**

## List of Meta-Owned IT Assets

1. **[BeyondTrust Remote Support Software](https://www.beyondtrust.com/products/remote-support)**: It allows support organizations to access and assist remote computers and mobile devices. The following Facebook assets host this software:

    - https://btremotesupport.thefacebook.com/appliance/login.ns - Virtual Appliance LOGIN
    - https://btremotesupport.thefacebook.com/ - Support Portal
    - https://remoteassist-east.thefacebook.com/ - Support Portal
    - https://remoteassist-west.thefacebook.com/ - Support Portal
    - https://remoteassist.thefacebook.com/ - Support Portal
    - https://remoteassist.thefacebook.com/api/command.xsd

    Additionally, some interesting technical guidelines and product documentation for BeyondTrust Remote Support Software can be found publicly at [rs-admin.pdf](https://www.beyondtrust.com/docs/remote-support/documents/user/rs-admin.pdf).

2. **Excalidraw**: Excalidraw is a virtual collaborative whiteboard tool that allows users to easily sketch diagrams with a hand-drawn feel. It is an open-source tool available on GitHub at [excalidraw/excalidraw](https://github.com/excalidraw/excalidraw). The following Facebook assets host Excalidraw:

    - https://whiteboard.facebookrecruiting.com/
    - https://excalidraw.glbx.thefacebook.com/
    - https://excalidraw.thefacebook.com/
    - https://excalidrawsocket.thefacebook.com/

3. **MuleSoft's APIkit**: APIkit is a tool developed by MuleSoft for building Mule REST or SOAP APIs. It is an open-source project available on GitHub at [mulesoft/apikit](https://github.com/mulesoft/apikit). The following Facebook assets expose APIkit Console:

    - https://ash-mulesoftrtuat.thefacebook.com/console/ - UAT
    - https://ash-mulesoftrtprd.thefacebook.com/console/ - Prod

4. **Cortex DAM**: Cortex DAM is a digital asset management platform developed by [Orange Logic](https://www.orangelogic.com/). It is hosted on the following Facebook-owned domains:

    - https://cortex.thefacebook.com/CS.aspx?VP3=LoginRegistration&L=True&R=False
    - https://cortex.atmeta.com/CS.aspx?VP3=LoginRegistration&L=True&R=False
    - https://cortex-uat.atmeta.com/CS.aspx?VP3=LoginRegistration&L=True&R=False
    - https://cortex.thefacebook.com/API/Authentication/v1.0/Login

5. **[F5 BIG-IP Access Policy Manager](https://www.f5.com/products/big-ip-services/access-policy-manager)**: The F5 BIG-IP Access Policy Manager (APM) is a solution that enables users or organizations to utilize single sign-on (SSO) for accessing applications from anywhere. You can find the manual, supplemental documents, and release notes for BIG-IP APM [here](https://my.f5.com/manage/s/tech-documents#t=prodManuals&sort=relevancy&f:@f5_product=[BIG-IP%20APM]). For other interesting technical documents related to F5 products, you can use the following Google dork: [site:f5.com "my.policy" ext:pdf](https://www.google.com/search?q=site%3Af5.com+%22my.policy%22+ext%3Apdf). Subdomains hosting BIG-IP APM:

    - https://snc-agile-ext.thefacebook.com/
    - https://ash-agile-ext.thefacebook.com/

6. **[Verdaccio](https://verdaccio.org/)**: Verdaccio is a lightweight Node.js private proxy registry. It is an open-source project available on GitHub at [verdaccio/verdaccio](https://github.com/verdaccio/verdaccio). Facebook assets hosting Verdaccio:

    - https://npm.developer.glbx.thefacebook.com/
    - https://npm.developer.glbx.thefacebook.com/-/metrics
    - https://npm.developer.glbx.thefacebook.com/-/static/manifest.json
    - https://npm.developer.oculus.com/

7. **TAP - PROD**: TAP (possibly short for "The Authentication Provider") appears to be an [identity server](https://duendesoftware.com/products/identityserver), but further details are unknown. The unmaintained and archived code related to the identity server is available as an open-source project on GitHub at [IdentityServer](https://github.com/IdentityServer). Subdomains associated with TAP - PROD:

    - https://legal.tapprd.thefacebook.com/
    - https://legal.tapprd.thefacebook.com/tapprd/portal
    - https://legal.tapprd.thefacebook.com/tapprd/auth/identity/connect/authorize?client_id=9d7955e505af4cd48be38c2447b35638&response_type=code&scope=web_ui%20offline_access%20openid&redirect_uri=https%3A%2F%2Flegal.tapprd.thefacebook.com%2Ftapprd%2Fportal%2Fauthentication%2Fcallback&state=%2Ftapprd%2FPortal%2F%3Alocal&acr_values=local&prompt=login
    - https://lb-snc-tapprdngx.thefacebook.com/

8. **[Neurons for MDM](https://www.ivanti.com/products/ivanti-neurons-for-mdm)**: Neurons for MDM (Mobile Device Management) is a cloud-based platform for modern device management developed by Ivanti (formerly MobileIron). You can find relevant technical documents and information about Neurons for MDM online, such as the [Low User Impact Migration Portal 11 Guide](https://help.ivanti.com/mi/help/en_us/cld/11/mig/LandingPage.htm), [Ivanti Neurons for MDM (N-MDM) Migration Resource Toolkit](https://forums.ivanti.com/s/article/MobileIron-Migration-Resource-Toolkit-4904?language=en_US), and [MobileIron Migration Portal User Guide - Product Documentation](https://help.ivanti.com/mi/legacypdfs/MobileIron%20Low%20User%20Impact%20Migration%20Portal%20R10%20User%20Guide.pdf). Facebook assets related to Neurons for MDM:

    - https://vsp-int.thefacebook.com/ - LUI (Low User Impact) Migration Portal
    - https://vsp-int.thefacebook.com/user#!/ - Device Migration Portal
    - https://vsp-int.thefacebook.com/auriga/v2/api-docs - Swagger API Documentation (Viewable using [Swagger Editor](https://editor.swagger.io/))
    - https://vsp-int.thefacebook.com/auriga/status
    - https://ec2-54-160-23-184.compute-1.amazonaws.com/

9. **[Velociraptor](https://docs.velociraptor.app/)**: Velociraptor is an advanced digital forensic and incident response tool used for collecting host-based state information using the Velociraptor Query Language (VQL) queries. It is an open-source project available on GitHub at [Velocidex/velociraptor](https://github.com/Velocidex/velociraptor). Facebook asset hosting Velociraptor:

    - https://minion.lr-test.atmeta.com/app/index.html
    - https://minion.lr-test.atmeta.com/server.pem

10. **[Zendesk](https://www.zendesk.com/in/)**: Zendesk is a customer support platform. Facebook asset hosting Zendesk:

    - https://help.mapillary.com/hc/en-us
    - https://facebookbrand-2018-dev.fb.com/

11. **[WordPress](https://wordpress.com/)**: WordPress is a popular content management system. Facebook asset hosting WordPress:

    - https://facebookbrand-2018-release.fb.com/wp-login.php
    - https://facebookbrand-2018-preprod.fb.com/wp-login.php
    - https://*.facebookbrand-2018-release.fb.com/wp-login.php
    - https://*.facebookbrand-2018-preprod.fb.com/wp-login.php
    - https://code-dev.fb.com/wp-login.php
    - https://abpstories.fb.com/wp-login.php
    - https://360.fb.com/wp-login.php
    - https://audio360.fb.com/wp-login.php
    - https://about.fb.com/wp-login.php
    - https://brasil.fb.com/wp-login.php
    - https://apacpolicy.fb.com/wp-login.php
    - https://360video.fb.com/wp-login.php
    - https://access.fb.com/wp-login.php
    - https://countryhub.fb.com/wp-login.php
    - https://counterspeech.fb.com/wp-login.php
    - https://emeapolicycovidhub.fb.com/wp-login.php
    - https://engineering.fb.com/wp-login.php
    - https://estacaohack.fb.com/wp-login.php
    - https://facebookbrand-2018-release.fb.com/wp-login.php
    - https://fightcovidmisinfo.fb.com/wp-login.php
    - https://facebook360.fb.com/wp-login.php
    - https://indonesia.fb.com/wp-login.php
    - https://immersivelearningacademy.fb.com/wp-login.php
    - https://humanrights.fb.com/wp-login.php
    - https://india.fb.com/wp-login.php
    - https://myanmar.fb.com/wp-login.php
    - https://managingbias.fb.com/wp-login.php
    - https://mydigitalworld.fb.com/wp-login.php
    - https://programswhatsapp.fb.com/wp-login.php
    - https://privacytech.fb.com/wp-login.php
    - https://rightsmanager.fb.com/wp-login.php
    - https://sustainability.fb.com/wp-login.php
    - https://messengernews.fb.com/wp-login.php
    - https://surround360.fb.com/wp-login.php
    - https://whatsapppolicy.fb.com/wp-login.php
    - https://vrforinclusion.fb.com/wp-login.php
    - https://wethinkdigital.fb.com/wp-login.php
    - https://code.fb.com/wp-login.php

12. **[Cisco ASA VPN](https://www.cisco.com/site/us/en/index.html)**: Cisco ASA VPN is a virtual private network solution. The following Facebook assets host this software:

    - https://ams501vpn.thefacebook.com/
    - https://ams501vpn01.thefacebook.com/
    - https://ams501vpn02.thefacebook.com/
    - https://ams501vpn03.thefacebook.com/
    - https://ashvpn.thefacebook.com/
    - https://ashvpn01.thefacebook.com/
    - https://ashvpn02.thefacebook.com/
    - https://ashvpn03.thefacebook.com/
    - https://ashvpn04.thefacebook.com/
    - https://ashvpn05.thefacebook.com/
    - https://ashvpn06.thefacebook.com/
    - https://gruvpn.thefacebook.com/
    - https://gruvpn01.thefacebook.com/
    - https://gruvpn02.thefacebook.com/
    - https://lhr501vpn.thefacebook.com/
    - https://lhr501vpn01.thefacebook.com/
    - https://lhr501vpn02.thefacebook.com/
    - https://nrt502vpn.thefacebook.com/
    - https://nrt502vpn01.thefacebook.com/
    - https://nrt502vpn02.thefacebook.com/
    - https://sin501vpn.thefacebook.com/
    - https://sin501vpn01.thefacebook.com/
    - https://sin501vpn02.thefacebook.com/
    - https://sncvpn.thefacebook.com/
    - https://sncvpn01.thefacebook.com/
    - https://sncvpn02.thefacebook.com/
    - https://sncvpn03.thefacebook.com/
    - https://sncvpn04.thefacebook.com/
    - https://sncvpn05.thefacebook.com/
    - https://sncvpn06.thefacebook.com/

  > If you're interested in learning about subdomain naming conventions used by Facebook, you can read more about it [here](https://unorde.red/exploring-facebooks-network/).

13. **[Phabricator](https://phacility.com/phabricator/)**: Phabricator is an open-source software development collaboration platform. Available on GitHub at [phacility/phabricator](https://github.com/phacility/phabricator). Facebook assets related to Phabricator:

    - https://phabricatorfiles.internmc.fb.com/
    - https://phabricatorfiles.cstools.fb.com/
    - https://phabricatorfiles.intern.fb.com/
    - https://phabricator.internmc.fb.com/
    - https://phabricator.cstools.fb.com/
    - https://phabricator.intern.fb.com/

14. **Facebook Employee Login**: 

    - https://fb.workplace.com/
    - https://fb.alpha.workplace.com/
    - https://work.meta.com/

15. **Open Source Software Repositories**: 

    - https://mirror.facebook.net/
    - http://mirror.t.tfbnw.net/
    - https://mirror.glbx.thefacebook.com/
    - https://github.com/facebook/
    - https://github.com/facebookincubator/

16. **Google Dorks**: _(Note: Google search results may vary based on locality and ISP.)_

    - [site:go.facebookinc.com](https://www.google.com/search?q=site%3Ago.facebookinc.com) OR [site:legal.tapprd.thefacebook.com inurl:ShowWorkFlow](https://www.google.com/search?q=site:legal.tapprd.thefacebook.com+inurl:ShowWorkFlow) - Google dork to find interesting Forms. 
    - [site:facebook.com inurl:"facebook.com/ajax" ext:php](https://www.google.com/search?q=site:facebook.com+inurl:%22facebook.com/ajax%22+ext:php) - Google dork to find interesting PHP controller files. 
    - [site:facebook.com inurl:"security/advisories" intitle:CVE](https://www.google.com/search?q=site:facebook.com+inurl:%22security/advisories%22+intitle:CVE) - Google dork to find security advisories published by Facebook.

17. **URL shortening service**: Shortened URL service provided by Facebook. 

    - https://fb.me/
    - https://on.fb.me/
    - https://go.fb.me/
    - https://fburl.com/

18. **Critical assets**: These in-house developed assets are hosting user-sensitive data:

    - https://graph.facebook.com/ - It is a key subdomain used for GraphQL API requests. It serves as the entry point for making GraphQL queries. A beta version of Facebook's Graph API is available at https://graph.beta.facebook.com/. Similarly, for Instagram, the subdomains https://graph.instagram.com/ and https://graphql.instagram.com/ are utilized for interacting with Instagram's GraphQL API.
    - https://www.internalfb.com/ - It is a domain Facebook uses internally.
    - https://www.facebook.com/records/login/ - This portal is used to respond to matters involving imminent harm to a child or risk of death or serious physical injury to any person. Law enforcement officials can submit requests for information disclosure without delay. It is likely an in-house developed portal.
    - https://www.metacareers.com/ and http://www.facebookrecruiting.com/ - Meta Careers is a portal for recruitment, internships, and joining Meta. 
    - https://developers.facebook.com/tools/ - It provides various interesting debugging and validation tools helpful for developers.
    - https://upload.facebook.com/ - It is responsible for handling file uploads to Facebook. When users upload photos or videos, the files are typically processed and stored through this subdomain.
    - https://www.beta.facebook.com/ - Used to test new features and updates before they are rolled out to the main Facebook platform. Read more [here](https://developers.facebook.com/blog/post/438/).
    - https://auth.meta.com/ - Authentication purposes in the Meta ecosystem.

19. **[Microsoft Exchange Autodiscover](https://learn.microsoft.com/en-us/exchange/architecture/client-access/autodiscover?view=exchserver-2019)**:

    - http://autodiscover.thefacebook.com/autodiscover/
    - http://autodiscover.fb.com/autodiscover/

20. **Other Interesting Domains and Endpoints**:
    - https://www.facebook.com/diagnostics
    - https://b-api.facebook.com/method/auth.login
    - https://api.facebook.com/restserver.php?api_key=win3zz&format=XML&method=facebook.fql.query&query=SELECT
    - https://www.facebook.com/status.php - Endpoint for checking the status of Facebook's services.
    - https://www.facebook.com/ai.php
    - https://www.facebook.com/plugins/serverfbml.php
    - https://www.facebook.com/osd.xml
    - https://m.facebook.com/.well-known/keybase.txt - Endpoint for accessing the Keybase verification file on mobile Facebook.
    - https://facebooksuppliers.com/ - Endpoint for accessing information related to Facebook's suppliers.
    - https://www.facebook.com/suppliers/diversity/enroll - Endpoint for enrolling in Facebook's diversity supplier program.
    - https://www.facebookblueprint.com/
    - https://code.facebook.com/cla - Endpoint for accessing Facebook's Contributor License Agreement.
    - https://phishme.thefacebook.com/ 
    - https://trac.thefacebook.com/
    - https://pki.thefacebook.com/
    - https://badge.thefacebook.com/
    - https://vip.thefacebook.com/
    - https://trunkstable.facebook.com/
    - https://www.trunkstable.instagram.com/
    - https://trunkstable.freebasics.com/
    - https://connect-staging.internet.org/
    - https://edge-chat.internalfb.com/
    - https://s-static.internalfb.com/
    - https://apacpolicy.fb.com/login-page/
    - https://whatsapppolicy.fb.com/login-page/
    - https://emeapolicycovidhub.fb.com/vpn/
    - https://dev.freebasics.com/
    - https://cinyour.facebook.com/
    - https://content.facebookinc.com/
    - https://instagram-engineering.com/
    - https://maps.instagram.com/
    - https://gateway.horizon.meta.com/
    - https://gateway.quest.meta.com/
    - https://gateway.spark.meta.com/
    - https://gateway.internalfb.com/
    - https://gateway.work.meta.com/
    - https://communityforums.atmeta.com/
    - https://communityforums-stage.atmeta.com/
    - https://forum.mapillary.com/
    - https://simulator.freebasics.com/
    - https://spark.meta.com/
    - https://datastories.fb.com/
    - https://middlemileinfra.fb.com/
    - https://npe.fb.com/
    - https://qpdemocheckin.fb.com/
    - https://vestibule.fb.com/
    - https://test.supernova.fb.com/
    - https://vsp.fb.com/
    - https://rightsmanager.fb.com/
    - https://developerevents.atmeta.com/
    - [https://developerevents.atmeta.com/gql?query={__schema{types{name}}}](https://developerevents.atmeta.com/gql?query={__schema{types{name}}}) - This GraphQL endpoint that allows processing introspection queries.
    - https://ec2-52-86-181-233.compute-1.amazonaws.com/ - An AWS host owned by Facebook. It hosts a Node.js application named Mango Harvest. 
    - https://ec2-52-86-181-233.compute-1.amazonaws.com/api/docs/ - Swagger UI instance
    - https://ec2-52-86-181-233.compute-1.amazonaws.com/api/api/ - Stacktrace 

## Other Information

- **Snapshot of Facebook from February 12, 2004**: You can explore the early days of Facebook by viewing a snapshot of the website. 
    - https://web.archive.org/web/20040212031928/http://www.thefacebook.com/
- **Facebook Inventory**: A collection of Facebook assets available on GitHub.
    - https://github.com/TricksterShubi/inventory/tree/main/Facebook
- **Facebook Bug Bounty Writeups**: A collection of vulnerability reports on Facebook.
    - https://github.com/jaiswalakshansh/Facebook-BugBounty-Writeups
- **Facebook Source Code Leaked**:
    - https://gist.github.com/nikcub/3833406
    - https://gist.github.com/philfreo/7257723
- **Email ID of Mark Zuckerberg**: zuck@thefacebook.com (Ref: https://twitter.com/testerfo1/status/1538880004536139776) 
- **Facebook Profile of Mark Zuckerberg**: https://www.facebook.com/profile.php?id=4 OR https://www.facebook.com/zuck

_Please note that at the time of writing, all the URLs mentioned in the list are accessible. However, keep in mind that the availability of these URLs may change over time. I will do my best to update if any URLs become inaccessible._

### Contribution
If you know any interesting assets/URLs that are dynamic in nature, host open-source or third-party applications, or if you know of applications developed by Meta itself, please feel free to submit a pull request. Additionally, individuals can share PoC they consider important or security-sensitive, even if they haven't been accepted by Facebook as bugs.
