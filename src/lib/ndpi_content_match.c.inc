/*
 * ndpi_content_match.c
 *
 * Copyright (C) 2011-2017 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* ****************************************************** */


/* ****************************************************** */

/*
  Host-based match

  HTTP:  Server: field
  HTTPS: Server certificate name

  Risk classification criteria
  ----------------------------

  NDPI_PROTOCOL_SAFE
    - Web sites (and CDNs) which are not commonly used to host malicious activities.
    - OS update hosts.
    - App stores.
    - Commonly used services with passwords in encrypted channels (SMTPS, POPS, etc)

  NDPI_PROTOCOL_ACCEPTABLE
    - Cloud services may be used to host malware (e.g., https://www.fireeye.com/blog/threat-research/2015/11/china-based-threat.html),
      but it is mostly used for normal purposes.
    - Webmail sites, which can be used to phising.
    - Encrypted administrative protocols, such as SSH.
    - Text, voice or video communication (e.g., Skype, Slack, Whatsapp).
    - Ads services are commonly used to spread malware
      (https://www.tripwire.com/state-of-security/security-data-protection/crypto-ransomware-spreads-via-poisoned-ads-on-major-websites/)

  NDPI_PROTOCOL_FUN
    - Social media sites and services.
    - Communication used for fun purposes, like Snapchat, Tinder, etc.
    - Audio and videostreamming services (e.g., Netflix).
    - Game services.

  NDPI_PROTOCOL_UNSAFE
    - Unencrypted administrative protocols, such as Telnet.
    - Cloud hosted servers when accessed by default domains, such as *.amazonaws.com.
        - "AWS Supports 41% of Malware Hosting Sites, More than Any Other Web Host or ISP"
          http://www.thewhir.com/web-hosting-news/aws-supports-41-malware-hosting-sites-web-host-isp
        - https://www.scmagazine.com/600-plus-cloud-repositories-spotted-hosting-malware-and-malicious-files/article/572205/
        - https://howtoremove.guide/remove-s3-amazonaws-virus/
    - Torrents.
    - Commonly used services with passwords in unencrypted channels (SMTP, POP, etc)

  NDPI_PROTOCOL_POTENTIALLY_DANGEROUS
    - Tor and other anonymization access.
    - Sites commonly used to host malware and not as commonly used by "normal" users. (e.g., pastebin.com)
      https://isc.sans.edu/forums/diary/Many+Malware+Samples+Found+on+Pastebin/22036/

  NDPI_PROTOCOL_UNRATED
    - Avoid this class.

*/

ndpi_protocol_match host_match[] = {
  { "s3.ll.dash.row.aiv-cdn.net", NULL, "s3\\.ll\\.dash\\.row\\.aiv-cdn\\.net",  "AmazonVideo",      NDPI_PROTOCOL_AMAZON_VIDEO, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { "d25xi40x97liuc.cloudfront.net", NULL, "d25xi40x97liuc\\.cloudfront\\.net",  "AmazonVideo",      NDPI_PROTOCOL_AMAZON_VIDEO, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { ".aiv-delivery.net", NULL, "\\.aiv-delivery\\.net",                          "AmazonVideo",      NDPI_PROTOCOL_AMAZON_VIDEO, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { "amazon.", NULL, NULL,                                 "Amazon",           NDPI_PROTOCOL_AMAZON, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { "amazon.com", NULL, "amazon\\.com$",                   "Amazon",           NDPI_PROTOCOL_AMAZON, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { "images-amazon.com", NULL, "images-amazon\\.com$",     "Amazon",           NDPI_PROTOCOL_AMAZON, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },
  { "amazonaws.com", NULL, "amazonaws\\.com$",             "Amazon",           NDPI_PROTOCOL_AMAZON, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },
  { "amazon-adsystem.com", NULL, "amazon-adsystem\\.com$", "Amazon",           NDPI_PROTOCOL_AMAZON, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },
  { ".cloudfront.net", NULL, "\\.cloudfront\\.net$",       "Amazon",           NDPI_PROTOCOL_AMAZON, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },

  { ".push.apple.com", NULL, NULL,          "ApplePush",        NDPI_PROTOCOL_APPLE_PUSH, NDPI_PROTOCOL_CATEGORY_CLOUD, NDPI_PROTOCOL_SAFE },
  { ".apple-dns.net", NULL, NULL,           "Apple",            NDPI_PROTOCOL_APPLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".mzstatic.com", NULL, NULL,            "Apple",            NDPI_PROTOCOL_APPLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".aaplimg.com", NULL, NULL,             "Apple",            NDPI_PROTOCOL_APPLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { "iosapps.itunes.apple.com", NULL, NULL, "AppleStore",       NDPI_PROTOCOL_APPLESTORE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE }, /* iOS */
  { "osxapps.itunes.apple.com", NULL, NULL, "AppleStore",       NDPI_PROTOCOL_APPLESTORE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE }, /* MacOS */
  { "buy.itunes.apple.com", NULL, NULL,     "AppleStore",       NDPI_PROTOCOL_APPLESTORE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE },
  { "su.itunes.apple.com", NULL, NULL,      "AppleStore",       NDPI_PROTOCOL_APPLESTORE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE },
  { "se.itunes.apple.com", NULL, NULL,      "AppleStore",       NDPI_PROTOCOL_APPLESTORE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE },
  { "myapp.itunes.apple.com", NULL, NULL,   "AppleStore",       NDPI_PROTOCOL_APPLESTORE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE },
  { "swscan.apple.com", NULL, NULL,         "AppleStore",       NDPI_PROTOCOL_APPLESTORE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE },
  { "itunes-apple.com", NULL, NULL,         "AppleStore",       NDPI_PROTOCOL_APPLESTORE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE },
  { "itunes.apple.com", NULL, NULL,         "AppleiTunes",      NDPI_PROTOCOL_APPLE_ITUNES, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { "aaplimg.com", NULL, NULL,              "Apple",            NDPI_PROTOCOL_APPLE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE },
  { ".apple.com", NULL, NULL,               "Apple",            NDPI_PROTOCOL_APPLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".icloud.com", NULL, NULL,              "AppleiCloud",      NDPI_PROTOCOL_APPLE_ICLOUD, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },

  { ".cnn.c", NULL, NULL,                   "CNN",              NDPI_PROTOCOL_CNN, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".cnn.net", NULL, NULL,                 "CNN",              NDPI_PROTOCOL_CNN, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },

  { ".dropbox.com", NULL, NULL,             "DropBox",          NDPI_PROTOCOL_DROPBOX, NDPI_PROTOCOL_CATEGORY_CLOUD, NDPI_PROTOCOL_ACCEPTABLE },
  { ".dropboxstatic.com", NULL, NULL,       "DropBox",          NDPI_PROTOCOL_DROPBOX, NDPI_PROTOCOL_CATEGORY_CLOUD, NDPI_PROTOCOL_ACCEPTABLE },
  { ".dropbox-dns.com", NULL, NULL,         "DropBox",          NDPI_PROTOCOL_DROPBOX, NDPI_PROTOCOL_CATEGORY_CLOUD, NDPI_PROTOCOL_ACCEPTABLE },
  { "log.getdropbox.com", NULL, NULL,       "DropBox",          NDPI_PROTOCOL_DROPBOX, NDPI_PROTOCOL_CATEGORY_CLOUD, NDPI_PROTOCOL_ACCEPTABLE },

  { ".ebay.", NULL, NULL,                   "eBay",             NDPI_PROTOCOL_EBAY, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE }, /* or FUN */
  { ".ebay.com", NULL, NULL,                "eBay",             NDPI_PROTOCOL_EBAY, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".ebaystatic.com", NULL, NULL,          "eBay",             NDPI_PROTOCOL_EBAY, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".ebaydesc.com", NULL, NULL,            "eBay",             NDPI_PROTOCOL_EBAY, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".ebayrtm.com", NULL, NULL,             "eBay",             NDPI_PROTOCOL_EBAY, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".ebaystratus.com", NULL, NULL,         "eBay",             NDPI_PROTOCOL_EBAY, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".ebayimg.com", NULL, NULL,             "eBay",             NDPI_PROTOCOL_EBAY, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },

  { "facebook.com", NULL, NULL,             "Facebook",         NDPI_PROTOCOL_FACEBOOK, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { "fbstatic-a.akamaihd.net", NULL, NULL,  "Facebook",         NDPI_PROTOCOL_FACEBOOK, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { ".fbcdn.net", NULL, NULL,               "Facebook",         NDPI_PROTOCOL_FACEBOOK, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { "fbcdn-", NULL, NULL,                   "Facebook",         NDPI_PROTOCOL_FACEBOOK, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { ".facebook.net", NULL, NULL,            "Facebook",         NDPI_PROTOCOL_FACEBOOK, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },

  { ".speedtest.net", NULL, NULL,           "Ookla",            NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_CATEGORY_NETWORK, NDPI_PROTOCOL_SAFE },

  { "docs.googleusercontent.com", NULL, NULL, "GoogleDocs",     NDPI_PROTOCOL_GOOGLE_DOCS, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_ACCEPTABLE },
  
  { "drive-thirdparty.googleusercontent.com", NULL, NULL,        "GoogleDrive",      NDPI_PROTOCOL_GOOGLE_DRIVE, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { "drive.google.com",                       NULL, NULL,        "GoogleDrive",      NDPI_PROTOCOL_GOOGLE_DRIVE, NDPI_PROTOCOL_CATEGORY_CLOUD, NDPI_PROTOCOL_ACCEPTABLE },

  { "android.clients.google.com", NULL, NULL,   "PlayStore",    NDPI_PROTOCOL_PLAYSTORE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE },
  { "ggpht.com", NULL, NULL,                    "PlayStore",    NDPI_PROTOCOL_PLAYSTORE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE },

  /*
     See https://better.fyi/trackers/

     DoubleClick by Google (2mdn.net)
     DoubleClick by Google (doubleclick.net)
     DoubleClick by Google, Inc. (dmtry.com)
     Google AdSense by Google (google.com)
     Google AdSense by Google (google.se)
     Google AdSense by Google (googleadservices.com)
     Google Analytics by Google (google-analytics.com)
     Google APIs by Google (ajax.googleapis.com)
     Google Fonts by Google (fonts.googleapis.com)
     Google Interactive Media Ads (imasdk.googleapis.com)
     Google Syndication (googlesyndication.com)
     Google Tag Manager by Google (googletagmanager.com)
     Google Tag Manager by Google (googletagservices.com)
     Gstatic by Google (gstatic.com)
  */

  /* Google Advertisements */
  { ".googlesyndication.com", NULL, NULL,   "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_TRACKER_ADS },
  { "googleads.", NULL, NULL,               "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_TRACKER_ADS },
  { ".doubleclick.net", NULL, NULL,         "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_TRACKER_ADS },
  { "googleadservices.", NULL, NULL,        "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_TRACKER_ADS },
  { ".2mdn.net", NULL, NULL,                "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_TRACKER_ADS },
  { ".dmtry.com", NULL, NULL,               "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_TRACKER_ADS },
  { "google-analytics.", NULL, NULL,        "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_TRACKER_ADS },

  /* Google Services */
  { "googleapis.com", NULL, NULL,           "GoogleServices",   NDPI_PROTOCOL_GOOGLE_SERVICES, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },
  { ".googletagservices.com", NULL, NULL,   "GoogleServices",   NDPI_PROTOCOL_GOOGLE_SERVICES, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },
  { "mtalk.google.com", NULL, NULL,         "GoogleServices",   NDPI_PROTOCOL_GOOGLE_SERVICES, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },

  { "plus.google.com", NULL, NULL,          "GooglePlus",       NDPI_PROTOCOL_GOOGLE_PLUS, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { "plus.url.google.com", NULL, NULL,      "GooglePlus",       NDPI_PROTOCOL_GOOGLE_PLUS, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },

  /* http://check.googlezip.net/connect [check browser connectivity] */
  { ".googlezip.net", NULL, NULL,           "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },

  { "docs.googleusercontent.com", NULL, NULL, "GoogleDocs",     NDPI_PROTOCOL_GOOGLE_DOCS, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_ACCEPTABLE },
  { "docs.google.com",            NULL, NULL, "GoogleDocs",     NDPI_PROTOCOL_GOOGLE_DOCS, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_ACCEPTABLE },
    
  { "googleusercontent.com", NULL, NULL,    "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE }, 
  { "1e100.net", NULL, NULL,                "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },

  { "maps.google.", NULL, NULL,             "GoogleMaps",       NDPI_PROTOCOL_GOOGLE_MAPS, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { "maps.gstatic.com", NULL, NULL,         "GoogleMaps",       NDPI_PROTOCOL_GOOGLE_MAPS, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },

  { ".gmail.", NULL, NULL,                  "GMail",            NDPI_PROTOCOL_GMAIL, NDPI_PROTOCOL_CATEGORY_MAIL, NDPI_PROTOCOL_ACCEPTABLE },
  { "mail.google.", NULL, NULL,             "GMail",            NDPI_PROTOCOL_GMAIL, NDPI_PROTOCOL_CATEGORY_MAIL, NDPI_PROTOCOL_ACCEPTABLE },

  { "google.", NULL, NULL,                  "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".google.", NULL, NULL,                 "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".gstatic.com", NULL, NULL,             "Google",           NDPI_PROTOCOL_GOOGLE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },

  { "mail.outlook.com", NULL, NULL,         "Hotmail",          NDPI_PROTOCOL_HOTMAIL, NDPI_PROTOCOL_CATEGORY_MAIL, NDPI_PROTOCOL_ACCEPTABLE },

  { ".last.fm", NULL, NULL,                 "LastFM",           NDPI_PROTOCOL_LASTFM, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },

  { "msn.com", NULL, NULL,                  "MSN",              NDPI_PROTOCOL_MSN, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE }, /* News site */

  { "netflix.com", NULL, NULL,              "NetFlix",          NDPI_PROTOCOL_NETFLIX, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { "nflxext.com", NULL, NULL,              "NetFlix",          NDPI_PROTOCOL_NETFLIX, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { "nflximg.com", NULL, NULL,              "NetFlix",          NDPI_PROTOCOL_NETFLIX, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { "nflximg.net", NULL, NULL,              "NetFlix",          NDPI_PROTOCOL_NETFLIX, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { "nflxvideo.net", NULL, NULL,            "NetFlix",          NDPI_PROTOCOL_NETFLIX, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },

  { ".skype.", NULL, NULL,                  "Skype",            NDPI_PROTOCOL_SKYPE, NDPI_PROTOCOL_CATEGORY_VOIP, NDPI_PROTOCOL_ACCEPTABLE },
  { ".skypeassets.", NULL, NULL,            "Skype",            NDPI_PROTOCOL_SKYPE, NDPI_PROTOCOL_CATEGORY_VOIP, NDPI_PROTOCOL_ACCEPTABLE },
  { ".skypedata.", NULL, NULL,              "Skype",            NDPI_PROTOCOL_SKYPE, NDPI_PROTOCOL_CATEGORY_VOIP, NDPI_PROTOCOL_ACCEPTABLE },
  { ".skypeecs-", NULL, NULL,               "Skype",            NDPI_PROTOCOL_SKYPE, NDPI_PROTOCOL_CATEGORY_VOIP, NDPI_PROTOCOL_ACCEPTABLE },
  { ".skypeforbusiness.", NULL, NULL,       "Skype",            NDPI_PROTOCOL_SKYPE, NDPI_PROTOCOL_CATEGORY_VOIP, NDPI_PROTOCOL_ACCEPTABLE },
  { ".lync.com", NULL, NULL,                "Skype",            NDPI_PROTOCOL_SKYPE, NDPI_PROTOCOL_CATEGORY_VOIP, NDPI_PROTOCOL_ACCEPTABLE },
  { "e7768.b.akamaiedge.net", NULL, NULL,   "Skype",            NDPI_PROTOCOL_SKYPE, NDPI_PROTOCOL_CATEGORY_VOIP, NDPI_PROTOCOL_ACCEPTABLE },
  { "e4593.dspg.akamaiedge.net", NULL, NULL,"Skype",            NDPI_PROTOCOL_SKYPE, NDPI_PROTOCOL_CATEGORY_VOIP, NDPI_PROTOCOL_ACCEPTABLE },
  { "e4593.g.akamaiedge.net", NULL, NULL,   "Skype",            NDPI_PROTOCOL_SKYPE, NDPI_PROTOCOL_CATEGORY_VOIP, NDPI_PROTOCOL_ACCEPTABLE },

  { ".tuenti.com", NULL, NULL,              "Tuenti",           NDPI_PROTOCOL_TUENTI, NDPI_PROTOCOL_CATEGORY_VOIP, NDPI_PROTOCOL_ACCEPTABLE },

  { ".twttr.com", NULL, NULL,               "Twitter",          NDPI_PROTOCOL_TWITTER, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { "twitter.", NULL, NULL,                 "Twitter",          NDPI_PROTOCOL_TWITTER, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { "twimg.com", NULL, NULL,                "Twitter",          NDPI_PROTOCOL_TWITTER, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },

  { ".viber.com", NULL, NULL,               "Viber",            NDPI_PROTOCOL_VIBER, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },
  { ".cdn.viber.com", NULL, NULL,           "Viber",            NDPI_PROTOCOL_VIBER, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },

  { "wikipedia.", NULL, NULL,               "Wikipedia",        NDPI_PROTOCOL_WIKIPEDIA, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { "wikimedia.", NULL, NULL,               "Wikipedia",        NDPI_PROTOCOL_WIKIPEDIA, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { "mediawiki.", NULL, NULL,               "Wikipedia",        NDPI_PROTOCOL_WIKIPEDIA, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { "wikimediafoundation.", NULL, NULL,     "Wikipedia",        NDPI_PROTOCOL_WIKIPEDIA, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },

  { ".whatsapp.", NULL, NULL,               "WhatsApp",         NDPI_PROTOCOL_WHATSAPP, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },

  { ".yahoo.", NULL, NULL,                  "Yahoo",            NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".yimg.com", NULL, NULL,                "Yahoo",            NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { "yahooapis.", NULL, NULL,               "Yahoo",            NDPI_PROTOCOL_YAHOO, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },

  { "upload.youtube.com", NULL, NULL,       "YouTubeUpload",    NDPI_PROTOCOL_YOUTUBE_UPLOAD, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "upload.video.google.com", NULL, NULL,  "YouTubeUpload",    NDPI_PROTOCOL_YOUTUBE_UPLOAD, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "youtube.", NULL, NULL,                 "YouTube",          NDPI_PROTOCOL_YOUTUBE, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "youtu.be.", NULL, NULL,                "YouTube",          NDPI_PROTOCOL_YOUTUBE, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "yt3.ggpht.com", NULL, NULL,            "YouTube",          NDPI_PROTOCOL_YOUTUBE, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { ".googlevideo.com", NULL, NULL,         "YouTube",          NDPI_PROTOCOL_YOUTUBE, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { ".ytimg.com", NULL, NULL,               "YouTube",          NDPI_PROTOCOL_YOUTUBE, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "youtube-nocookie.", NULL, NULL,        "YouTube",          NDPI_PROTOCOL_YOUTUBE, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "ggpht.com", NULL, NULL,                "YouTube",          NDPI_PROTOCOL_YOUTUBE, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },

  { ".vevo.com", NULL, NULL,                "Vevo",             NDPI_PROTOCOL_VEVO,    NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },

  { ".spotify.", NULL, NULL,                "Spotify",          NDPI_PROTOCOL_SPOTIFY, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "audio-fa.scdn.co", NULL, NULL,         "Spotify",          NDPI_PROTOCOL_SPOTIFY, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },


  { ".pandora.com", NULL, NULL,             "Pandora",          NDPI_PROTOCOL_PANDORA,  NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },

  { ".torproject.org", NULL, NULL,          "Tor",              NDPI_PROTOCOL_TOR, NDPI_PROTOCOL_CATEGORY_VPN, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS },

  { ".kakao.com", NULL, NULL,               "KakaoTalk",        NDPI_PROTOCOL_KAKAOTALK, NDPI_PROTOCOL_CATEGORY_VOIP, NDPI_PROTOCOL_ACCEPTABLE },

  { "ttvnw.net", NULL, NULL,                "Twitch",           NDPI_PROTOCOL_TWITCH, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "static-cdn.jtvnw.net", NULL, NULL,     "Twitch",           NDPI_PROTOCOL_TWITCH, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "www-cdn.jtvnw.net", NULL, NULL,        "Twitch",           NDPI_PROTOCOL_TWITCH, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },

  { "quickplay.com", NULL, NULL,            "QuickPlay",        NDPI_PROTOCOL_QUICKPLAY, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },

  { ".qq.com", NULL, NULL,                  "QQ",               NDPI_PROTOCOL_QQ, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },
  { ".gtimg.com", NULL, NULL,               "QQ",               NDPI_PROTOCOL_QQ, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },

  { ".weibo.com", NULL, NULL,               "Sina(Weibo)",      NDPI_PROTOCOL_SINA, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { ".sinaimg.cn", NULL, NULL,              "Sina",             NDPI_PROTOCOL_SINA, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { ".sinajs.cn", NULL, NULL,               "Sina",             NDPI_PROTOCOL_SINA, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { ".sina.cn", NULL, NULL,                 "Sina",             NDPI_PROTOCOL_SINA, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { ".sina.com.cn", NULL, NULL,             "Sina",             NDPI_PROTOCOL_SINA, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },

  /* https://support.cipafilter.com/index.php?/Knowledgebase/Article/View/117/0/snapchat---how-to-block */
  { "feelinsonice.appspot.com", NULL, "\\.appspot\\.com$",     "Snapchat",     NDPI_PROTOCOL_SNAPCHAT, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },
  { "feelinsonice-hrd.appspot.com", NULL, NULL, "Snapchat",     NDPI_PROTOCOL_SNAPCHAT, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },
  { "feelinsonice.com", NULL, "\\.feelsonice\\.com$",             "Snapchat",     NDPI_PROTOCOL_SNAPCHAT, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },
  { ".snapchat.", NULL, "\\.snapchat\\.com$",                   "Snapchat",     NDPI_PROTOCOL_SNAPCHAT, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },
  { ".snapads.", NULL, "\\.snapads\\.com$",                    "Snapchat",     NDPI_PROTOCOL_SNAPCHAT, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },

  /* Detected "instagram.c10r.facebook.com". Omitted "*amazonaws.com" and "*facebook.com" CDNs e.g. "ig-telegraph-shv-04-frc3.facebook.com" */
  { ".cdninstagram.com", NULL, NULL,        "Instagram",        NDPI_PROTOCOL_INSTAGRAM, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { "instagram.", NULL, NULL,               "Instagram",        NDPI_PROTOCOL_INSTAGRAM, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { ".instagram.", NULL, NULL,              "Instagram",        NDPI_PROTOCOL_INSTAGRAM, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { "igcdn-photos-", NULL, NULL,            "Instagram",        NDPI_PROTOCOL_INSTAGRAM, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { "instagramimages-", NULL, NULL,         "Instagram",        NDPI_PROTOCOL_INSTAGRAM, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { "instagramstatic-", NULL, NULL,         "Instagram",        NDPI_PROTOCOL_INSTAGRAM, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },

  { ".waze.com", NULL, NULL,                "Waze",             NDPI_PROTOCOL_WAZE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },

  { ".deezer.com", NULL, NULL,              "Deezer",           NDPI_PROTOCOL_DEEZER, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },

  { ".microsoft.com", NULL, NULL,           "Microsoft",        NDPI_PROTOCOL_MICROSOFT, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { "i-msdn.sec.s-msft.com", NULL, NULL,    "Microsoft",        NDPI_PROTOCOL_MICROSOFT, NDPI_PROTOCOL_CATEGORY_SYSTEM_OS, NDPI_PROTOCOL_ACCEPTABLE },
  { "i2-msdn.sec.s-msft.com", NULL, NULL,   "Microsoft",        NDPI_PROTOCOL_MICROSOFT, NDPI_PROTOCOL_CATEGORY_SYSTEM_OS, NDPI_PROTOCOL_ACCEPTABLE },
  { ".webtrends.com", NULL, NULL,           "Microsoft",        NDPI_PROTOCOL_MICROSOFT, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },
  { ".msecnd.net", NULL, NULL,              "Microsoft",        NDPI_PROTOCOL_MICROSOFT, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },
  { "bing.com", NULL, NULL,                 "Microsoft",        NDPI_PROTOCOL_MICROSOFT, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_SAFE },
  { ".visualstudio.com", NULL, NULL,        "Microsoft",        NDPI_PROTOCOL_MICROSOFT, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_SAFE },

  { "bn1301.storage.live.com", NULL, NULL,      "MS_OneDrive",  NDPI_PROTOCOL_MS_ONE_DRIVE,NDPI_PROTOCOL_CATEGORY_CLOUD,  NDPI_PROTOCOL_ACCEPTABLE },
  { "*.gateway.messenger.live.com", NULL, NULL, "MS_OneDrive",  NDPI_PROTOCOL_MS_ONE_DRIVE, NDPI_PROTOCOL_CATEGORY_CLOUD, NDPI_PROTOCOL_ACCEPTABLE },
  { "skyapi.live.net", NULL, NULL,              "MS_OneDrive",  NDPI_PROTOCOL_MS_ONE_DRIVE, NDPI_PROTOCOL_CATEGORY_CLOUD, NDPI_PROTOCOL_ACCEPTABLE },
  { "d.docs.live.net", NULL, NULL,              "MS_OneDrive",  NDPI_PROTOCOL_MS_ONE_DRIVE, NDPI_PROTOCOL_CATEGORY_CLOUD, NDPI_PROTOCOL_ACCEPTABLE },

  { "update.microsoft.com", NULL, NULL,     "WindowsUpdate",    NDPI_PROTOCOL_WINDOWS_UPDATE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE },
  { ".windowsupdate.com", NULL, NULL,       "WindowsUpdate",    NDPI_PROTOCOL_WINDOWS_UPDATE, NDPI_PROTOCOL_CATEGORY_SW_UPDATE, NDPI_PROTOCOL_SAFE },

  { "worldofwarcraft.com", NULL, NULL,      "WorldOfWarcraft",  NDPI_PROTOCOL_WORLDOFWARCRAFT, NDPI_PROTOCOL_CATEGORY_GAME, NDPI_PROTOCOL_FUN },

  { ".anchorfree.", NULL, NULL,             "HotspotShield",    NDPI_PROTOCOL_HOTSPOT_SHIELD, NDPI_PROTOCOL_CATEGORY_VPN, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS },
  { "hotspotshield.com", NULL, NULL,        "HotspotShield",    NDPI_PROTOCOL_HOTSPOT_SHIELD, NDPI_PROTOCOL_CATEGORY_VPN, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS },
  { ".northghost.com", NULL, NULL,          "HotspotShield",    NDPI_PROTOCOL_HOTSPOT_SHIELD, NDPI_PROTOCOL_CATEGORY_VPN, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS },

  { ".webex.com", NULL, NULL,               "Webex",            NDPI_PROTOCOL_WEBEX, NDPI_PROTOCOL_CATEGORY_VOIP, NDPI_PROTOCOL_ACCEPTABLE },

  { ".ocsdomain.com", NULL, NULL,           "OCS",              NDPI_PROTOCOL_OCS, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "ocs.fr", NULL, NULL,                   "OCS",              NDPI_PROTOCOL_OCS, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { ".ocs.fr", NULL, NULL,                  "OCS",              NDPI_PROTOCOL_OCS, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { ".labgency.ws", NULL, NULL,             "OCS",              NDPI_PROTOCOL_OCS, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },

  { ".iflix.com", NULL, NULL,               "IFLIX",            NDPI_PROTOCOL_IFLIX, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { ".app.iflixcorp.com", NULL, NULL,       "IFLIX",            NDPI_PROTOCOL_IFLIX, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { ".images.iflixassets.com", NULL, NULL,  "IFLIX",            NDPI_PROTOCOL_IFLIX, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },

  { "crl.microsoft.com", NULL, NULL,            "Office365",    NDPI_PROTOCOL_OFFICE_365, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { "evsecure-ocsp.verisign.com", NULL, NULL,   "Office365",    NDPI_PROTOCOL_OFFICE_365, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { "evsecure-aia.verisign.com", NULL, NULL,    "Office365",    NDPI_PROTOCOL_OFFICE_365, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { "evsecure-crl.verisign.com", NULL, NULL,    "Office365",    NDPI_PROTOCOL_OFFICE_365, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".omniroot.com", NULL, NULL,                "Office365",    NDPI_PROTOCOL_OFFICE_365, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".microsoftonline.com", NULL, NULL,         "Office365",    NDPI_PROTOCOL_OFFICE_365, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".office365.com", NULL, NULL,               "Office365",    NDPI_PROTOCOL_OFFICE_365, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".office.com", NULL, NULL,                  "Office365",    NDPI_PROTOCOL_OFFICE_365, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".msocsp.com", NULL, NULL,                  "Office365",    NDPI_PROTOCOL_OFFICE_365, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".msocdn.com", NULL, NULL,                  "Office365",    NDPI_PROTOCOL_OFFICE_365, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },

  /* http://www.urlquery.net/report.php?id=1453233646161 */
  { "lifedom.top", NULL, NULL,              "Cloudflare",       NDPI_PROTOCOL_CLOUDFLARE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },
  { "coby.ns.cloudflare.com", NULL, NULL,   "Cloudflare",       NDPI_PROTOCOL_CLOUDFLARE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },
  { "amanda.ns.cloudflare.com", NULL, NULL, "Cloudflare",       NDPI_PROTOCOL_CLOUDFLARE, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },

  { "d295hzzivaok4k.cloudfront.net", NULL, NULL,"OpenDNS",      NDPI_PROTOCOL_OPENDNS, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },
  { ".opendns.com", NULL, NULL,                 "OpenDNS",      NDPI_PROTOCOL_OPENDNS, NDPI_PROTOCOL_CATEGORY_NETWORK, NDPI_PROTOCOL_ACCEPTABLE },

  /* https://get.slack.help/hc/en-us/articles/205138367-Troubleshooting-Slack-connection-issues */
  { "slack.com", NULL, NULL,                "Slack",            NDPI_PROTOCOL_SLACK, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".slack-msgs.com", NULL, NULL,          "Slack",            NDPI_PROTOCOL_SLACK, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { "slack-files.com", NULL, NULL,          "Slack",            NDPI_PROTOCOL_SLACK, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { "slack-imgs.com", NULL, NULL,           "Slack",            NDPI_PROTOCOL_SLACK, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".slack-edge.com", NULL, NULL,          "Slack",            NDPI_PROTOCOL_SLACK, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".slack-core.com", NULL, NULL,          "Slack",            NDPI_PROTOCOL_SLACK, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { "slack-redir.net", NULL, NULL,          "Slack",            NDPI_PROTOCOL_SLACK, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  /* Detected "slack-assets2.s3-us-west-2.amazonaws.com.". Omitted "*amazonaws.com" CDN, but no generic pattern to use on first part */
  { "slack-assets2.s3-", NULL, NULL,        "Slack",            NDPI_PROTOCOL_SLACK, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },

  { "github.com", NULL, NULL,               "Github",           NDPI_PROTOCOL_GITHUB, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".github.com", NULL, NULL,              "Github",           NDPI_PROTOCOL_GITHUB, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { "github.io", NULL, NULL,                "Github",           NDPI_PROTOCOL_GITHUB, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".github.io", NULL, NULL,               "Github",           NDPI_PROTOCOL_GITHUB, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { "githubusercontent.com", NULL, NULL,    "Github",           NDPI_PROTOCOL_GITHUB, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".githubusercontent.com", NULL, NULL,   "Github",           NDPI_PROTOCOL_GITHUB, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },

  { ".iqiyi.com", NULL, NULL,               "iQIYI",            NDPI_PROTOCOL_IQIYI, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { ".qiyi.com", NULL, NULL,                "iQIYI",            NDPI_PROTOCOL_IQIYI, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { ".71.am", NULL, NULL,                   "iQIYI",            NDPI_PROTOCOL_IQIYI, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { ".qiyipic.com", NULL, NULL,             "iQIYI",            NDPI_PROTOCOL_IQIYI, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },

  { ".ppstream.com", NULL, NULL,            "PPStream",         NDPI_PROTOCOL_PPSTREAM, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { ".pps.tv", NULL, NULL,                  "PPStream",         NDPI_PROTOCOL_PPSTREAM, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },

  { ".1kxun.", NULL, NULL,                  "1kxun",            NDPI_PROTOCOL_1KXUN, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { "tcad.wedolook.com", NULL, NULL,        "1kxun",            NDPI_PROTOCOL_1KXUN, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },

  { ".steampowered.com", NULL, NULL,            "Steam",        NDPI_PROTOCOL_STEAM, NDPI_PROTOCOL_CATEGORY_GAME, NDPI_PROTOCOL_FUN },
  { "steamcommunity.com", NULL, NULL,           "Steam",        NDPI_PROTOCOL_STEAM, NDPI_PROTOCOL_CATEGORY_GAME, NDPI_PROTOCOL_FUN },
  { ".steamcontent.com", NULL, NULL,            "Steam",        NDPI_PROTOCOL_STEAM, NDPI_PROTOCOL_CATEGORY_GAME, NDPI_PROTOCOL_FUN },
  { ".steamstatic.com", NULL, NULL,             "Steam",        NDPI_PROTOCOL_STEAM, NDPI_PROTOCOL_CATEGORY_GAME, NDPI_PROTOCOL_FUN },
  { "steamcommunity-a.akamaihd.net", NULL, NULL,"Steam",        NDPI_PROTOCOL_STEAM, NDPI_PROTOCOL_CATEGORY_GAME, NDPI_PROTOCOL_FUN },

  { ".wechat.com", NULL, NULL,              "WeChat",           NDPI_PROTOCOL_WECHAT, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },
  { ".wechat.org", NULL, NULL,              "WeChat",           NDPI_PROTOCOL_WECHAT, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },
  { ".wechatapp.com", NULL, NULL,           "WeChat",           NDPI_PROTOCOL_WECHAT, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },
  { ".we.chat", NULL, NULL,                 "WeChat",           NDPI_PROTOCOL_WECHAT, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },
  { ".wx.", NULL, NULL,                     "WeChat",           NDPI_PROTOCOL_WECHAT, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },
  { ".weixin.", NULL, NULL,                 "WeChat",           NDPI_PROTOCOL_WECHAT, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },
  { ".mmsns.qpic.cn", NULL, NULL,           "WeChat",           NDPI_PROTOCOL_WECHAT, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_FUN },

  { "dnscrypt.org", NULL, NULL,             "DNScrypt",         NDPI_PROTOCOL_DNSCRYPT, NDPI_PROTOCOL_CATEGORY_NETWORK, NDPI_PROTOCOL_ACCEPTABLE },

  { "torrent.", NULL, NULL,                 "BitTorrent",       NDPI_PROTOCOL_BITTORRENT, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_UNSAFE },
  { "torrents.", NULL, NULL,                "BitTorrent",       NDPI_PROTOCOL_BITTORRENT, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_UNSAFE },
  { "torrentz.", NULL, NULL,                "BitTorrent",       NDPI_PROTOCOL_BITTORRENT, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_UNSAFE },

  { ".nintendo.net", NULL, NULL,            "Nintendo",         NDPI_PROTOCOL_NINTENDO, NDPI_PROTOCOL_CATEGORY_GAME, NDPI_PROTOCOL_FUN },
  { ".nintendo.com", NULL, NULL,            "Nintendo",         NDPI_PROTOCOL_NINTENDO, NDPI_PROTOCOL_CATEGORY_GAME, NDPI_PROTOCOL_FUN },
  { ".playstation.net", NULL, NULL,             "Playstation",  NDPI_PROTOCOL_PLAYSTATION, NDPI_PROTOCOL_CATEGORY_GAME, NDPI_PROTOCOL_FUN },
  { ".playstation.com", NULL, NULL,             "Playstation",  NDPI_PROTOCOL_PLAYSTATION, NDPI_PROTOCOL_CATEGORY_GAME, NDPI_PROTOCOL_FUN },
  { ".sonyentertainmentnetwork.com", NULL, NULL,"Playstation",  NDPI_PROTOCOL_PLAYSTATION, NDPI_PROTOCOL_CATEGORY_GAME, NDPI_PROTOCOL_FUN },

  { ".pastebin.com", NULL, NULL,            "Pastebin",         NDPI_PROTOCOL_PASTEBIN, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS },

  { ".linkedin.com", NULL, NULL,            "LinkedIn",         NDPI_PROTOCOL_LINKEDIN, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { ".licdn.com", NULL, NULL,               "LinkedIn",         NDPI_PROTOCOL_LINKEDIN, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },

  { ".sndcdn.com", NULL, NULL,              "SoundCloud",       NDPI_PROTOCOL_SOUNDCLOUD, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { ".soundcloud.com", NULL, NULL,          "SoundCloud",       NDPI_PROTOCOL_SOUNDCLOUD, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },
  { "getrockerbox.com", NULL, NULL,         "SoundCloud",       NDPI_PROTOCOL_SOUNDCLOUD, NDPI_PROTOCOL_CATEGORY_STREAMING, NDPI_PROTOCOL_FUN },

  { "web.telegram.org", NULL, NULL,         "Telegram",         NDPI_PROTOCOL_TELEGRAM, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },
  { "tdesktop.com", NULL, NULL,             "Telegram",         NDPI_PROTOCOL_TELEGRAM, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },
  { "tupdate.com", NULL, NULL,              "Telegram",         NDPI_PROTOCOL_TELEGRAM, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },

  { ".icq.", NULL, NULL,                    "ICQ",              NDPI_PROTOCOL_ICQ, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },
  { "icq.", NULL, NULL,                     "ICQ",              NDPI_PROTOCOL_ICQ, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },

  { NULL, NULL, NULL, 0 }
};


/*
  Mime-type content match match
*/
ndpi_protocol_match content_match[] = {
  { "audio/mpeg",                   NULL, NULL, NULL,           NDPI_CONTENT_MPEG, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "audio/x-mpeg",                 NULL, NULL, NULL,           NDPI_CONTENT_MPEG, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "audio/mpeg3",                  NULL, NULL, NULL,           NDPI_CONTENT_MPEG, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "audio/mp4a",                   NULL, NULL, NULL,           NDPI_CONTENT_MPEG, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "video/mpeg",                   NULL, NULL, NULL,           NDPI_CONTENT_MPEG, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "video/nsv",                    NULL, NULL, NULL,           NDPI_CONTENT_MPEG, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "misc/ultravox",                NULL, NULL, NULL,           NDPI_CONTENT_MPEG, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "audio/ogg",                    NULL, NULL, NULL,           NDPI_CONTENT_OGG, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "video/ogg",                    NULL, NULL, NULL,           NDPI_CONTENT_OGG, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "application/ogg",              NULL, NULL, NULL,           NDPI_CONTENT_OGG, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { ".adobe.",                      NULL, NULL, NULL,           NDPI_CONTENT_FLASH, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "video/flv",                    NULL, NULL, NULL,           NDPI_CONTENT_FLASH, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "video/x-flv",                  NULL, NULL, NULL,           NDPI_CONTENT_FLASH, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "application/x-fcs",            NULL, NULL, NULL,           NDPI_CONTENT_FLASH, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "application/x-shockwave-flash",NULL, NULL, NULL,           NDPI_CONTENT_FLASH, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_ACCEPTABLE },
  { "video/flash",                  NULL, NULL, NULL,           NDPI_CONTENT_FLASH, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "application/flv",              NULL, NULL, NULL,           NDPI_CONTENT_FLASH, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "flv-application/octet-stream", NULL, NULL, NULL,           NDPI_CONTENT_FLASH, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "application/futuresplash",     NULL, NULL, NULL,           NDPI_CONTENT_FLASH, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "video/quicktime",              NULL, NULL, NULL,           NDPI_CONTENT_QUICKTIME, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "video/mp4",                    NULL, NULL, NULL,           NDPI_CONTENT_QUICKTIME, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "video/x-m4v",                  NULL, NULL, NULL,           NDPI_CONTENT_QUICKTIME, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "audio/x-pn-realaudio",         NULL, NULL, NULL,           NDPI_CONTENT_REALMEDIA, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "application/vnd.rn-realmedia", NULL, NULL, NULL,           NDPI_CONTENT_REALMEDIA, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "video/x-ms-",                  NULL, NULL, NULL,           NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "asf",                          NULL, NULL, NULL,           NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "asx",                          NULL, NULL, NULL,           NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "video/x-msvideo",              NULL, NULL, NULL,           NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "audio/x-wav",                  NULL, NULL, NULL,           NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "application/vnd.ms.wms-hdr.asfv1", NULL, NULL, NULL,       NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "NSPlayer/",                    NULL, NULL, NULL,           NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "application/x-mms-framed",     NULL, NULL, NULL,           NDPI_CONTENT_MMS, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "Xbox Live Client/",            NULL, NULL, NULL,           NDPI_PROTOCOL_XBOX, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "Windows-Update-Agent",         NULL, NULL, NULL,           NDPI_PROTOCOL_WINDOWS_UPDATE, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_ACCEPTABLE },
  { "audio/webm",                   NULL, NULL, NULL,           NDPI_CONTENT_WEBM, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "video/webm",                   NULL, NULL, NULL,           NDPI_CONTENT_WEBM, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "application/x-rtsp-tunnelled", NULL, NULL, NULL,           NDPI_PROTOCOL_RTSP, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "application/vnd.apple.mpegurl",NULL, NULL, NULL,           NDPI_CONTENT_MPEG, NDPI_PROTOCOL_CATEGORY_MEDIA, NDPI_PROTOCOL_FUN },
  { "application/x-tar",            NULL, NULL, NULL,           NDPI_PROTOCOL_HTTP_DOWNLOAD, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_ACCEPTABLE },
  { "application/octet-stream",     NULL, NULL, NULL,           NDPI_PROTOCOL_HTTP_DOWNLOAD, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_ACCEPTABLE },
  { "application/mac-binary",       NULL, NULL, NULL,           NDPI_PROTOCOL_HTTP_DOWNLOAD, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_ACCEPTABLE },
  { "/x-bzip",                      NULL, NULL, NULL,           NDPI_PROTOCOL_HTTP_DOWNLOAD, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_ACCEPTABLE },
  { "/x-gzip",                      NULL, NULL, NULL,           NDPI_PROTOCOL_HTTP_DOWNLOAD, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_ACCEPTABLE },
  { "/x-zip",                       NULL, NULL, NULL,           NDPI_PROTOCOL_HTTP_DOWNLOAD, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_ACCEPTABLE },
  { "/zip",                         NULL, NULL, NULL,           NDPI_PROTOCOL_HTTP_DOWNLOAD, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_ACCEPTABLE },
  { "binhex",                       NULL, NULL, NULL,           NDPI_PROTOCOL_HTTP_DOWNLOAD, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_ACCEPTABLE },
  { "/base64",                      NULL, NULL, NULL,           NDPI_PROTOCOL_HTTP_DOWNLOAD, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_ACCEPTABLE },
  { "application/gnutar",           NULL, NULL, NULL,           NDPI_PROTOCOL_HTTP_DOWNLOAD, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_ACCEPTABLE },
  { "application/x-compressed",     NULL, NULL, NULL,           NDPI_PROTOCOL_HTTP_DOWNLOAD, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_ACCEPTABLE },

  { NULL, NULL, NULL, 0 }
};

/* ****************************************************** */

/*
  Tor
  The tor protocol uses SSL to contact peers so it could be exchanged with
  standard SSL. However the host names such as

  - www.fgd2iwya7vinfutj5wq5we.com
  - www.qbtxzhetq4s2f.com
  - www.fgd2iwya7vinfutj5wq5we.net

  See also DGA (Domain Generation Algorithm)

  In essence www.<name>.com|net

  To do things properly we should check if host name in the certificate
  exists or if the IP address of the SSL peer resolves to a name. Unfortunately
  for performance reasons we can't afford to do a DNS lookup in nDPI (however apps
  can do it if possible) and thus we have created a heuristic algorithm that tries
  to check the host name (in the SSL certificate) to see if it looks like a
  random name or a real name. We cannot use a dictionary (how can the kernel read a file?)
  and this we use bigrams distribution to decide if the string looks like a
  word or just random chars.

  http://www3.nd.edu/~busiforc/handouts/cryptography/Letter%20Frequencies.html
*/

static const char *ndpi_en_bigrams[] = {
  "aa", "ba", "ca", "da", "ea", "fa", "ga", "ha", "ia", "ja", "ka", "la", "ma", "na", "oa", "pa", "qa",
  "ra", "sa", "ta", "ua", "va", "wa", "xa", "ya", "za", "ab", "bb", "db", "eb", "fb", "gb", "hb", "ib",
  "kb", "lb", "mb", "nb", "ob", "pb", "rb", "sb", "tb", "ub", "wb", "yb", "ac", "bc", "cc", "dc", "ec",
  "fc", "gc", "hc", "ic", "kc", "lc", "mc", "nc", "oc", "pc", "rc", "sc", "tc", "uc", "wc", "xc", "yc",
  "ad", "bd", "cd", "dd", "ed", "fd", "gd", "hd", "id", "kd", "ld", "md", "nd", "od", "pd", "rd", "sd",
  "td", "ud", "wd", "xd", "yd", "zd", "ae", "be", "ce", "de", "ee", "fe", "ge", "he", "ie", "je", "ke",
  "le", "me", "ne", "oe", "pe", "re", "se", "te", "ue", "ve", "we", "xe", "ye", "ze", "af", "bf", "df",
  "ef", "ff", "gf", "hf", "if", "kf", "lf", "mf", "nf", "of", "pf", "rf", "sf", "tf", "uf", "wf", "xf",
  "yf", "zf", "ag", "bg", "dg", "eg", "fg", "gg", "hg", "ig", "kg", "lg", "ng", "og", "pg", "rg", "sg",
  "tg", "ug", "wg", "yg", "ah", "bh", "ch", "dh", "eh", "fh", "gh", "hh", "ih", "kh", "lh", "mh", "nh",
  "oh", "ph", "rh", "sh", "th", "uh", "wh", "xh", "yh", "ai", "bi", "ci", "di", "ei", "fi", "gi", "hi",
  "ii", "ji", "ki", "li", "mi", "ni", "oi", "pi", "qi", "ri", "si", "ti", "ui", "vi", "wi", "xi", "yi",
  "zi", "aj", "bj", "dj", "ej", "fj", "gj", "hj", "ij", "jj", "kj", "lj", "nj", "oj", "pj", "rj", "sj",
  "tj", "uj", "wj", "yj", "ak", "ck", "dk", "ek", "gk", "ik", "kk", "lk", "mk", "nk", "ok", "pk", "rk",
  "sk", "tk", "uk", "wk", "yk", "zk", "al", "bl", "cl", "dl", "el", "fl", "gl", "hl", "il", "kl", "ll",
  "ml", "nl", "ol", "pl", "rl", "sl", "tl", "ul", "vl", "wl", "xl", "yl", "zl", "am", "bm", "cm", "dm",
  "em", "fm", "gm", "hm", "im", "km", "lm", "mm", "nm", "om", "pm", "rm", "sm", "tm", "um", "wm", "xm",
  "ym", "zm", "an", "bn", "cn", "dn", "en", "fn", "gn", "hn", "in", "kn", "ln", "mn", "nn", "on", "pn",
  "rn", "sn", "tn", "un", "wn", "xn", "yn", "ao", "bo", "co", "do", "eo", "fo", "go", "ho", "io", "jo",
  "ko", "lo", "mo", "no", "oo", "po", "ro", "so", "to", "uo", "vo", "wo", "xo", "yo", "zo", "ap", "bp",
  "dp", "ep", "fp", "gp", "hp", "ip", "kp", "lp", "mp", "np", "op", "pp", "rp", "sp", "tp", "up", "wp",
  "xp", "yp", "zp", "aq", "cq", "dq", "eq", "hq", "iq", "nq", "oq", "qq", "rq", "sq", "uq", "xq", "ar",
  "br", "cr", "dr", "er", "fr", "gr", "hr", "ir", "kr", "lr", "mr", "nr", "or", "pr", "rr", "sr", "tr",
  "ur", "vr", "wr", "xr", "yr", "as", "bs", "cs", "ds", "es", "fs", "gs", "hs", "is", "ks", "ls", "ms",
  "ns", "os", "ps", "rs", "ss", "ts", "us", "vs", "ws", "xs", "ys", "at", "bt", "ct", "dt", "et", "ft",
  "gt", "ht", "it", "kt", "lt", "mt", "nt", "ot", "pt", "rt", "st", "tt", "ut", "wt", "xt", "yt", "zt",
  "au", "bu", "cu", "du", "eu", "fu", "gu", "hu", "iu", "ju", "ku", "lu", "mu", "nu", "ou", "pu", "qu",
  "ru", "su", "tu", "uu", "vu", "wu", "xu", "yu", "zu", "av", "bv", "dv", "ev", "iv", "lv", "mv", "nv",
  "ov", "rv", "sv", "tv", "uv", "vv", "zv", "aw", "bw", "dw", "ew", "fw", "gw", "hw", "iw", "kw", "lw",
  "mw", "nw", "ow", "pw", "rw", "sw", "tw", "uw", "ww", "xw", "yw", "zw", "ax", "ex", "ix", "nx", "ox",
  "rx", "ux", "xx", "yx", "ay", "by", "cy", "dy", "ey", "fy", "gy", "hy", "ky", "ly", "my", "ny", "oy",
  "py", "ry", "sy", "ty", "uy", "vy", "wy", "xy", "yy", "zy", "az", "bz", "cz", "dz", "ez", "gz", "iz",
  "lz", "nz", "oz", "pz", "rz", "tz", "uz", "zz", NULL };

static const char *ndpi_en_impossible_bigrams[] = {
  "bk", "bq", "bx", "cb", "cf", "cg", "cj", "cp", "cv", "cw", "cx", "dx", "fk", "fq", "fv", "fx", /* "ee", removed it can be found in 'meeting' */
  "fz", "gq", "gv", "gx", "hh", "hk", "hv", "hx", "hz", "iy", "jb", "jc", "jd", "jf", "jg", "jh", "jk",
  "jl", "jm", "jn", "jp", "jq", "jr", /* "js", */ "jt", "jv", "jw", "jx", "jy", "jz", "kg", "kq", "kv", "kx",
  "kz", "lq", "lx", "mg", "mj", "mq", "mx", "mz", "pq", "pv", "px", "qb", "qc", "qd", "qe", "qf", "ii",
  "qg", "qh", "qj", "qk", "ql", "qm", "qn", "qo", "qp", "qr", "qs", "qt", "qv", "qw", "qx", "qy", "uu",
  "qz", "sx", "sz", "tq", "tx", "vb", "vc", "vd", "vf", "vg", "vh", "vj", "vm", "vn", "vp", "bw", /* "vk", "zr" Removed for kavkazr */
  "vq", "vt", "vw", "vx", "vz", "wq", "wv", "wx", "wz", "xb", "xg", "xj", "xk", "xv", "xz", "xw", "yd", /*"yp", Removed for paypal */
  "yj", "yq", "yv", "yz", "yw", "zb", "zc", "zg", "zh", "zj", "zn", "zq", "zs", "zx", "wh", "wk",
  "wb", "zk", "kp", "zk", "xy",
  NULL };
