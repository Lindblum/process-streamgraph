using System;

namespace ProcessStreamgraph
{
    /// <summary>
    /// What a connection is probably for, guessed from the host's name and the port: the service or
    /// API behind well-known hosts, then hints in the name's own words ("api", "telemetry", "cdn"),
    /// then what usually runs on the port. Traffic is encrypted, so this is a guess from the outside;
    /// it costs only a few string comparisons, made again only when a host's name changes.
    /// </summary>
    internal static class ServiceGuess
    {
        // Hosts and the domains under them, most specific first: the first match wins.
        private static readonly string[,] Hosts =
        {
            // Telemetry, analytics and ads.
            { "events.data.microsoft.com", "Windows/Office telemetry" },
            { "vortex.data.microsoft.com", "Windows telemetry" },
            { "telemetry.microsoft.com", "Microsoft telemetry" },
            { "browser.events.data.msn.com", "Edge telemetry" },
            { "google-analytics.com", "Analytics (Google)" },
            { "analytics.google.com", "Analytics (Google)" },
            { "app-measurement.com", "Analytics (Firebase)" },
            { "googletagmanager.com", "Analytics tags (Google)" },
            { "doubleclick.net", "Ads (Google)" },
            { "googlesyndication.com", "Ads (Google)" },
            { "googleadservices.com", "Ads (Google)" },
            { "adservice.google.com", "Ads (Google)" },
            { "amazon-adsystem.com", "Ads (Amazon)" },
            { "adnxs.com", "Ads (Xandr)" },
            { "criteo.com", "Ads (Criteo)" },
            { "taboola.com", "Ads (Taboola)" },
            { "outbrain.com", "Ads (Outbrain)" },
            { "scorecardresearch.com", "Audience tracking" },
            { "hotjar.com", "Session recording (Hotjar)" },
            { "clarity.ms", "Session recording (Clarity)" },
            { "segment.io", "Analytics (Segment)" },
            { "segment.com", "Analytics (Segment)" },
            { "mixpanel.com", "Analytics (Mixpanel)" },
            { "amplitude.com", "Analytics (Amplitude)" },
            { "datadoghq.com", "Monitoring (Datadog)" },
            { "newrelic.com", "Monitoring (New Relic)" },
            { "nr-data.net", "Monitoring (New Relic)" },
            { "sentry.io", "Crash reports (Sentry)" },
            { "bugsnag.com", "Crash reports (Bugsnag)" },
            { "crashlytics.com", "Crash reports (Crashlytics)" },
            { "watson.microsoft.com", "Crash reports (Windows)" },

            // AI services.
            { "api.anthropic.com", "Claude API" },
            { "claude.ai", "Claude" },
            { "api.openai.com", "OpenAI API" },
            { "chatgpt.com", "ChatGPT" },
            { "openai.com", "OpenAI" },
            { "generativelanguage.googleapis.com", "Gemini API" },
            { "gemini.google.com", "Gemini" },
            { "copilot.microsoft.com", "Copilot" },
            { "githubcopilot.com", "GitHub Copilot" },

            // Sign-in.
            { "login.microsoftonline.com", "Sign-in (Microsoft)" },
            { "login.live.com", "Sign-in (Microsoft account)" },
            { "accounts.google.com", "Sign-in (Google)" },
            { "oauth2.googleapis.com", "Sign-in (Google)" },
            { "appleid.apple.com", "Sign-in (Apple)" },
            { "okta.com", "Sign-in (Okta)" },
            { "auth0.com", "Sign-in (Auth0)" },

            // Updates and certificates.
            { "windowsupdate.com", "Windows Update" },
            { "update.microsoft.com", "Windows Update" },
            { "delivery.mp.microsoft.com", "Windows Update / Store downloads" },
            { "dl.delivery.mp.microsoft.com", "Windows Update / Store downloads" },
            { "displaycatalog.mp.microsoft.com", "Microsoft Store" },
            { "storeedgefd.dsx.mp.microsoft.com", "Microsoft Store" },
            { "smartscreen.microsoft.com", "SmartScreen check" },
            { "wdcp.microsoft.com", "Defender cloud check" },
            { "wd.microsoft.com", "Defender" },
            { "ocsp.digicert.com", "Certificate check" },
            { "crl.microsoft.com", "Certificate check" },
            { "pki.goog", "Certificate check" },
            { "lencr.org", "Certificate check" },
            { "time.windows.com", "Clock sync" },
            { "msftconnecttest.com", "Internet connectivity check" },
            { "msftncsi.com", "Internet connectivity check" },
            { "connectivitycheck.gstatic.com", "Internet connectivity check" },

            // Push notifications and live connections.
            { "wns.windows.com", "Push notifications (Windows)" },
            { "notify.windows.com", "Push notifications (Windows)" },
            { "mtalk.google.com", "Push notifications (Google)" },
            { "push.apple.com", "Push notifications (Apple)" },
            { "push.services.mozilla.com", "Push notifications (Firefox)" },

            // Microsoft.
            { "graph.microsoft.com", "Microsoft Graph API" },
            { "teams.microsoft.com", "Teams" },
            { "teams.live.com", "Teams" },
            { "skype.com", "Skype / Teams calls" },
            { "outlook.office365.com", "Outlook mail" },
            { "outlook.office.com", "Outlook mail" },
            { "onedrive.live.com", "OneDrive" },
            { "storage.live.com", "OneDrive files" },
            { "sharepoint.com", "SharePoint / OneDrive" },
            { "officeapps.live.com", "Office" },
            { "office.com", "Office" },
            { "office.net", "Office" },
            { "bing.com", "Bing" },
            { "msn.com", "MSN" },
            { "xboxlive.com", "Xbox Live" },
            { "blob.core.windows.net", "Azure file storage" },
            { "azureedge.net", "Azure CDN content" },
            { "azurefd.net", "Azure Front Door (web content)" },
            { "cloudapp.azure.com", "Azure-hosted service" },
            { "cloudapp.net", "Azure-hosted service" },
            { "azure.com", "Azure" },
            { "trafficmanager.net", "Azure-hosted service" },

            // Google.
            { "googlevideo.com", "YouTube video" },
            { "ytimg.com", "YouTube images" },
            { "youtube.com", "YouTube" },
            { "youtubei.googleapis.com", "YouTube API" },
            { "fonts.googleapis.com", "Web fonts" },
            { "fonts.gstatic.com", "Web fonts" },
            { "drive.google.com", "Google Drive" },
            { "docs.google.com", "Google Docs" },
            { "mail.google.com", "Gmail" },
            { "safebrowsing.googleapis.com", "Safe Browsing check" },
            { "update.googleapis.com", "Chrome updates" },
            { "clients2.google.com", "Chrome services" },
            { "googleapis.com", "Google APIs" },
            { "gstatic.com", "Google static files" },
            { "googleusercontent.com", "Google-hosted content" },
            { "1e100.net", "Google services" },
            { "google.com", "Google" },

            // Apple, Amazon, Meta and other platforms.
            { "icloud.com", "iCloud" },
            { "apple.com", "Apple services" },
            { "amazonaws.com", "Amazon cloud (AWS)" },
            { "cloudfront.net", "CDN content (CloudFront)" },
            { "amazon.com", "Amazon" },
            { "media-amazon.com", "Amazon images/video" },
            { "fbcdn.net", "Facebook/Instagram media" },
            { "facebook.com", "Facebook" },
            { "facebook.net", "Facebook (tracking pixel/SDK)" },
            { "instagram.com", "Instagram" },
            { "whatsapp.net", "WhatsApp" },
            { "twimg.com", "X/Twitter media" },
            { "x.com", "X/Twitter" },
            { "twitter.com", "X/Twitter" },
            { "reddit.com", "Reddit" },
            { "redd.it", "Reddit media" },
            { "linkedin.com", "LinkedIn" },
            { "licdn.com", "LinkedIn media" },
            { "tiktokcdn.com", "TikTok video" },
            { "tiktok.com", "TikTok" },

            // Developer services.
            { "api.github.com", "GitHub API" },
            { "githubusercontent.com", "GitHub files" },
            { "github.com", "GitHub" },
            { "githubassets.com", "GitHub web assets" },
            { "gitlab.com", "GitLab" },
            { "nuget.org", "NuGet packages" },
            { "npmjs.org", "npm packages" },
            { "npmjs.com", "npm packages" },
            { "pypi.org", "Python packages" },
            { "pythonhosted.org", "Python packages" },
            { "docker.io", "Docker images" },
            { "docker.com", "Docker" },
            { "visualstudio.com", "Visual Studio services" },
            { "vscode-cdn.net", "VS Code downloads" },
            { "vsassets.io", "VS Code extensions" },
            { "stackoverflow.com", "Stack Overflow" },

            // Chat, calls, media and games.
            { "slack.com", "Slack" },
            { "slack-edge.com", "Slack files" },
            { "discord.com", "Discord" },
            { "discordapp.com", "Discord" },
            { "discordapp.net", "Discord media" },
            { "discord.media", "Discord voice" },
            { "discord.gg", "Discord" },
            { "zoom.us", "Zoom" },
            { "webex.com", "Webex" },
            { "spotify.com", "Spotify" },
            { "scdn.co", "Spotify audio/images" },
            { "spotifycdn.com", "Spotify audio/images" },
            { "nflxvideo.net", "Netflix video" },
            { "netflix.com", "Netflix" },
            { "ttvnw.net", "Twitch video" },
            { "twitch.tv", "Twitch" },
            { "jtvnw.net", "Twitch images" },
            { "steamcontent.com", "Steam downloads" },
            { "steamserver.net", "Steam" },
            { "steampowered.com", "Steam" },
            { "steamstatic.com", "Steam images" },
            { "steamcommunity.com", "Steam Community" },
            { "epicgames.com", "Epic Games" },
            { "unrealengine.com", "Epic Games" },
            { "nvidia.com", "NVIDIA services" },
            { "adobe.com", "Adobe services" },
            { "adobe.io", "Adobe APIs" },
            { "dropbox.com", "Dropbox" },
            { "dropboxapi.com", "Dropbox API" },
            { "box.com", "Box" },

            // Browsers.
            { "brave.com", "Brave services" },
            { "bravesoftware.com", "Brave services" },
            { "mozilla.com", "Firefox services" },
            { "mozilla.net", "Firefox services" },
            { "mozilla.org", "Firefox services" },
            { "firefox.com", "Firefox services" },
            { "opera.com", "Opera services" },
            { "edge.microsoft.com", "Edge services" },

            // Delivery networks: the content is someone else's.
            { "akamaized.net", "CDN content (Akamai)" },
            { "akamaihd.net", "CDN content (Akamai)" },
            { "akamaiedge.net", "CDN content (Akamai)" },
            { "akamaitechnologies.com", "CDN content (Akamai)" },
            { "akamai.net", "CDN content (Akamai)" },
            { "edgekey.net", "CDN content (Akamai)" },
            { "edgesuite.net", "CDN content (Akamai)" },
            { "fastly.net", "CDN content (Fastly)" },
            { "fastlylb.net", "CDN content (Fastly)" },
            { "cloudflare.com", "Cloudflare" },
            { "cloudflare.net", "CDN content (Cloudflare)" },
            { "cdn77.org", "CDN content (CDN77)" },
            { "jsdelivr.net", "Web libraries (jsDelivr)" },
            { "cdnjs.cloudflare.com", "Web libraries (cdnjs)" },
            { "unpkg.com", "Web libraries (unpkg)" },
            { "llnwd.net", "CDN content (Limelight)" },
        };

        // Words in a host's name that hint at its use, checked when no host above matched.
        private static readonly string[,] Words =
        {
            { "telemetry", "Telemetry" }, { "analytics", "Analytics" }, { "metrics", "Metrics/telemetry" },
            { "stats", "Statistics/telemetry" }, { "collector", "Telemetry" }, { "beacon", "Tracking beacon" },
            { "events", "Event reporting" }, { "track", "Tracking" }, { "pixel", "Tracking pixel" },
            { "crash", "Crash reports" }, { "sentry", "Crash reports" }, { "log", "Logging" }, { "logs", "Logging" },
            { "ads", "Ads" }, { "ad", "Ads" }, { "adserver", "Ads" },
            { "api", "API" }, { "apis", "API" }, { "graphql", "API (GraphQL)" }, { "rest", "API" }, { "gateway", "API" },
            { "auth", "Sign-in" }, { "login", "Sign-in" }, { "oauth", "Sign-in" }, { "sso", "Sign-in" }, { "accounts", "Accounts/sign-in" },
            { "update", "Updates" }, { "updates", "Updates" }, { "download", "Downloads" }, { "downloads", "Downloads" }, { "dl", "Downloads" },
            { "cdn", "CDN content" }, { "static", "Static files" }, { "assets", "Web assets" }, { "img", "Images" },
            { "images", "Images" }, { "media", "Media" }, { "video", "Video" }, { "stream", "Streaming" },
            { "ws", "Live connection (WebSocket)" }, { "wss", "Live connection (WebSocket)" }, { "realtime", "Live updates" },
            { "push", "Push notifications" }, { "notify", "Notifications" }, { "sync", "Sync" }, { "upload", "Uploads" },
            { "storage", "File storage" }, { "files", "File storage" }, { "backup", "Backup" },
            { "mail", "Mail" }, { "smtp", "Mail" }, { "imap", "Mail" }, { "chat", "Chat" }, { "voice", "Voice" },
            { "ocsp", "Certificate check" }, { "crl", "Certificate check" }, { "ntp", "Clock sync" }, { "time", "Clock sync" },
            { "license", "License check" }, { "licensing", "License check" }, { "activation", "License check" },
            { "config", "Remote settings" }, { "settings", "Remote settings" }, { "flags", "Feature flags" },
        };

        /// <summary>
        /// The likely use of a connection to a host on a port: "GitHub API", "Telemetry?" (a hint from the
        /// name, marked with "?"), or what the port carries; "" when nothing is known.
        /// </summary>
        public static string Describe(string host, ushort port, bool udp)
        {
            string byName = FromName(host);
            if (byName != null) return byName;
            return ConnectionInfo.PortName(port, udp) ?? "";
        }

        private static string FromName(string host)
        {
            if (string.IsNullOrEmpty(host) || host.IndexOf('.') < 0) return null;
            host = host.TrimEnd('.').ToLowerInvariant();
            for (int i = 0; i < Hosts.GetLength(0); i++)
            {
                string domain = Hosts[i, 0];
                if (host.Length == domain.Length ? host == domain
                    : host.Length > domain.Length && host[host.Length - domain.Length - 1] == '.' && host.EndsWith(domain, StringComparison.Ordinal))
                    return Hosts[i, 1];
            }
            // The words of the name before its registered domain, with digits and dashes splitting them:
            // "api-eu2.example.com" gives "api" and "eu".
            string[] labels = host.Split('.');
            for (int l = 0; l < labels.Length - 2; l++)
                foreach (string word in labels[l].Split(new[] { '-', '_', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' }, StringSplitOptions.RemoveEmptyEntries))
                    for (int i = 0; i < Words.GetLength(0); i++)
                        if (word == Words[i, 0]) return Words[i, 1] + "?";
            return null;
        }
    }
}
