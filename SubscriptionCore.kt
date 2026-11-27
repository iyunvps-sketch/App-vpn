package app.myvpn.core

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLDecoder

// ---------------------------------------------------------------
// 1. Subscription download (Marzban: https://panel/sub/<token>)
// ---------------------------------------------------------------

data class SubInfo(
    val upload: Long = 0, val download: Long = 0, val total: Long = 0, val expire: Long = 0,
    val title: String? = null, val updateIntervalHours: Int? = null
)

data class Subscription(val info: SubInfo, val outbounds: List<JSONObject>, val rawSingBoxConfig: JSONObject?)

object SubscriptionFetcher {
    // Marzban picks the output format by User-Agent. A v2rayNG UA returns base64 links,
    // which is the most universal format and works with this parser.
    private const val UA = "v2rayNG/1.8.29"

    fun fetch(url: String): Subscription {
        val c = URL(url).openConnection() as HttpURLConnection
        c.setRequestProperty("User-Agent", UA)
        c.connectTimeout = 15000; c.readTimeout = 20000
        val body = c.inputStream.bufferedReader().use { it.readText() }
        val info = parseInfo(c.getHeaderField("subscription-userinfo"), c.getHeaderField("profile-title"),
            c.getHeaderField("profile-update-interval"))
        return SubscriptionParser.parse(body, info)
    }

    private fun parseInfo(userinfo: String?, title: String?, interval: String?): SubInfo {
        val m = userinfo?.split(";")?.mapNotNull {
            val p = it.trim().split("="); if (p.size == 2) p[0] to (p[1].toLongOrNull() ?: 0L) else null
        }?.toMap() ?: emptyMap()
        val t = title?.let { if (it.startsWith("base64:")) B64.decode(it.removePrefix("base64:")) else it }
        return SubInfo(m["upload"] ?: 0, m["download"] ?: 0, m["total"] ?: 0, m["expire"] ?: 0, t, interval?.toIntOrNull())
    }
}

// ---------------------------------------------------------------
// 2. Parser: all common protocols -> sing-box outbounds
// ---------------------------------------------------------------

object B64 {
    fun decode(s: String): String {
        var t = s.trim().replace('-', '+').replace('_', '/')
        while (t.length % 4 != 0) t += "="
        return String(java.util.Base64.getMimeDecoder().decode(t), Charsets.UTF_8)
    }
}

object SubscriptionParser {
    fun parse(body: String, info: SubInfo = SubInfo()): Subscription {
        val text = body.trim()
        // Case A: panel already returned a sing-box JSON config
        if (text.startsWith("{")) {
            val cfg = JSONObject(text)
            val outs = cfg.optJSONArray("outbounds") ?: JSONArray()
            val proxies = (0 until outs.length()).map { outs.getJSONObject(it) }
                .filter { it.optString("type") !in setOf("direct", "block", "dns", "selector", "urltest") }
            return Subscription(info, proxies, cfg)
        }
        // Case B: base64 list of links, or plain list of links
        val decoded = if (text.contains("://")) text else runCatching { B64.decode(text) }.getOrDefault(text)
        val used = HashSet<String>()
        val outs = decoded.lines().map { it.trim() }.filter { it.contains("://") }.mapNotNull { line ->
            runCatching { parseLink(line) }.getOrNull()
        }.map { o ->
            // make tags unique
            var tag = o.optString("tag").ifBlank { o.optString("server") }
            var n = 1; val base = tag
            while (!used.add(tag)) tag = "$base-${++n}"
            o.put("tag", tag)
        }
        return Subscription(info, outs, null)
    }

    fun parseLink(link: String): JSONObject = when (link.substringBefore("://").lowercase()) {
        "vless" -> vless(link)
        "vmess" -> vmess(link)
        "trojan" -> trojan(link)
        "ss" -> shadowsocks(link)
        "hysteria2", "hy2" -> hysteria2(link)
        "tuic" -> tuic(link)
        else -> throw IllegalArgumentException("Unsupported scheme: $link")
    }

    // ---- helpers ----
    private class L(val userInfo: String, val host: String, val port: Int, val q: Map<String, String>, val name: String)

    private fun dec(s: String) = URLDecoder.decode(s, "UTF-8")

    private fun split(raw: String): L {
        var rest = raw.substringAfter("://")
        val name = rest.substringAfter('#', "").let { if (it.isEmpty()) "" else dec(it) }
        rest = rest.substringBefore('#')
        val q = rest.substringAfter('?', "").split("&").filter { it.contains("=") }
            .associate { dec(it.substringBefore("=")) to dec(it.substringAfter("=")) }
        rest = rest.substringBefore('?').trimEnd('/')
        val userInfo = if (rest.contains('@')) rest.substringBeforeLast('@') else ""
        val hp = rest.substringAfterLast('@')
        val host: String; val port: Int
        if (hp.startsWith("[")) {
            host = hp.substring(1, hp.indexOf(']')); port = hp.substringAfter("]:").toInt()
        } else {
            host = hp.substringBeforeLast(':'); port = hp.substringAfterLast(':').toInt()
        }
        return L(dec(userInfo), host, port, q, name)
    }

    private fun tls(q: Map<String, String>, host: String, forceTls: Boolean = false): JSONObject? {
        val sec = q["security"] ?: if (forceTls) "tls" else "none"
        if (sec != "tls" && sec != "reality") return null
        val t = JSONObject().put("enabled", true)
            .put("server_name", q["sni"]?.ifBlank { null } ?: q["host"]?.ifBlank { null } ?: host)
        if (q["allowInsecure"] == "1" || q["insecure"] == "1") t.put("insecure", true)
        q["alpn"]?.takeIf { it.isNotBlank() }?.let { t.put("alpn", JSONArray(it.split(","))) }
        val fp = q["fp"]?.takeIf { it.isNotBlank() } ?: if (sec == "reality") "chrome" else null
        fp?.let { t.put("utls", JSONObject().put("enabled", true).put("fingerprint", it)) }
        if (sec == "reality") {
            t.put("reality", JSONObject().put("enabled", true)
                .put("public_key", q["pbk"] ?: "").put("short_id", q["sid"] ?: ""))
        }
        return t
    }

    private fun transport(q: Map<String, String>): JSONObject? {
        val host = q["host"]?.takeIf { it.isNotBlank() }
        return when (q["type"] ?: "tcp") {
            "ws" -> JSONObject().put("type", "ws").put("path", q["path"] ?: "/")
                .also { t -> host?.let { t.put("headers", JSONObject().put("Host", it)) } }
            "grpc" -> JSONObject().put("type", "grpc").put("service_name", q["serviceName"] ?: "")
            "httpupgrade" -> JSONObject().put("type", "httpupgrade").put("path", q["path"] ?: "/")
                .also { t -> host?.let { t.put("host", it) } }
            "http", "h2" -> JSONObject().put("type", "http").put("path", q["path"] ?: "/")
                .also { t -> host?.let { t.put("host", JSONArray(listOf(it))) } }
            else -> null // tcp / raw
        }
    }

    private fun base(type: String, l: L) = JSONObject().put("type", type)
        .put("tag", l.name.ifBlank { l.host }).put("server", l.host).put("server_port", l.port)

    // ---- protocols ----
    private fun vless(link: String): JSONObject {
        val l = split(link)
        val o = base("vless", l).put("uuid", l.userInfo)
        l.q["flow"]?.takeIf { it.isNotBlank() }?.let { o.put("flow", it) }
        tls(l.q, l.host)?.let { o.put("tls", it) }
        transport(l.q)?.let { o.put("transport", it) }
        return o
    }

    private fun trojan(link: String): JSONObject {
        val l = split(link)
        val o = base("trojan", l).put("password", l.userInfo)
        tls(l.q, l.host, forceTls = true)?.let { o.put("tls", it) }
        transport(l.q)?.let { o.put("transport", it) }
        return o
    }

    private fun vmess(link: String): JSONObject {
        val j = JSONObject(B64.decode(link.substringAfter("://")))
        val q = mutableMapOf(
            "type" to j.optString("net", "tcp"), "host" to j.optString("host"), "path" to j.optString("path"),
            "sni" to j.optString("sni"), "alpn" to j.optString("alpn"), "fp" to j.optString("fp"),
            "security" to if (j.optString("tls") == "tls") "tls" else "none",
            "serviceName" to j.optString("path")
        )
        val server = j.getString("add")
        val o = JSONObject().put("type", "vmess").put("tag", j.optString("ps").ifBlank { server })
            .put("server", server).put("server_port", j.get("port").toString().toInt())
            .put("uuid", j.getString("id")).put("alter_id", j.optString("aid", "0").toIntOrNull() ?: 0)
            .put("security", j.optString("scy").ifBlank { "auto" })
        tls(q, server)?.let { o.put("tls", it) }
        transport(q)?.let { o.put("transport", it) }
        return o
    }

    private fun shadowsocks(link: String): JSONObject {
        var rest = link.substringAfter("://")
        val name = rest.substringAfter('#', "").let { if (it.isEmpty()) "" else dec(it) }
        rest = rest.substringBefore('#')
        val plugin = rest.substringAfter("?plugin=", "").takeIf { it.isNotEmpty() }?.let { dec(it) }
        rest = rest.substringBefore('?').trimEnd('/')
        val method: String; val password: String; val host: String; val port: Int
        if (rest.contains('@')) {                       // SIP002
            val ui = rest.substringBeforeLast('@')
            val cred = if (ui.contains(':')) dec(ui) else B64.decode(ui)
            method = cred.substringBefore(':'); password = cred.substringAfter(':')
            val hp = rest.substringAfterLast('@')
            host = hp.substringBeforeLast(':').trim('[', ']'); port = hp.substringAfterLast(':').toInt()
        } else {                                        // legacy: base64(method:pass@host:port)
            val all = B64.decode(rest)
            method = all.substringBefore(':'); password = all.substringAfter(':').substringBeforeLast('@')
            val hp = all.substringAfterLast('@')
            host = hp.substringBeforeLast(':'); port = hp.substringAfterLast(':').toInt()
        }
        val o = JSONObject().put("type", "shadowsocks").put("tag", name.ifBlank { host })
            .put("server", host).put("server_port", port).put("method", method).put("password", password)
        plugin?.let {
            o.put("plugin", it.substringBefore(';')).put("plugin_opts", it.substringAfter(';', ""))
        }
        return o
    }

    private fun hysteria2(link: String): JSONObject {
        val l = split(link)
        val o = base("hysteria2", l).put("password", l.userInfo)
        o.put("tls", tls(l.q + ("security" to "tls"), l.host))
        l.q["obfs"]?.takeIf { it.isNotBlank() }?.let {
            o.put("obfs", JSONObject().put("type", it).put("password", l.q["obfs-password"] ?: ""))
        }
        return o
    }

    private fun tuic(link: String): JSONObject {
        val l = split(link)
        val o = base("tuic", l).put("uuid", l.userInfo.substringBefore(':'))
            .put("password", l.userInfo.substringAfter(':', ""))
            .put("congestion_control", l.q["congestion_control"] ?: "bbr")
            .put("udp_relay_mode", l.q["udp_relay_mode"] ?: "native")
        o.put("tls", tls(l.q + ("security" to "tls"), l.host))
        return o
    }
}

// ---------------------------------------------------------------
// 3. sing-box config builder (target: sing-box 1.11 / libbox)
// ---------------------------------------------------------------

object ConfigBuilder {
    fun build(proxies: List<JSONObject>, selectedTag: String? = null): JSONObject {
        require(proxies.isNotEmpty()) { "No servers in subscription" }
        val tags = proxies.map { it.getString("tag") }
        val outbounds = JSONArray()
        outbounds.put(JSONObject().put("type", "selector").put("tag", "proxy")
            .put("outbounds", JSONArray(listOf("auto") + tags))
            .put("default", selectedTag?.takeIf { it in tags } ?: "auto"))
        outbounds.put(JSONObject().put("type", "urltest").put("tag", "auto")
            .put("outbounds", JSONArray(tags))
            .put("url", "https://www.gstatic.com/generate_204").put("interval", "5m"))
        proxies.forEach { outbounds.put(it) }
        outbounds.put(JSONObject().put("type", "direct").put("tag", "direct"))

        return JSONObject()
            .put("log", JSONObject().put("level", "warn"))
            .put("dns", JSONObject()
                .put("servers", JSONArray()
                    .put(JSONObject().put("tag", "dns-remote").put("address", "https://1.1.1.1/dns-query").put("detour", "proxy"))
                    .put(JSONObject().put("tag", "dns-direct").put("address", "8.8.8.8").put("detour", "direct")))
                .put("rules", JSONArray().put(JSONObject().put("outbound", "any").put("server", "dns-direct")))
                .put("final", "dns-remote"))
            .put("inbounds", JSONArray().put(JSONObject()
                .put("type", "tun").put("tag", "tun-in")
                .put("address", JSONArray(listOf("172.19.0.1/30", "fdfe:dcba:9876::1/126")))
                .put("auto_route", true).put("strict_route", true).put("stack", "mixed")))
            .put("outbounds", outbounds)
            .put("route", JSONObject()
                .put("auto_detect_interface", true)
                .put("rules", JSONArray()
                    .put(JSONObject().put("action", "sniff"))
                    .put(JSONObject().put("protocol", "dns").put("action", "hijack-dns"))
                    .put(JSONObject().put("ip_is_private", true).put("outbound", "direct")))
                .put("final", "proxy"))
    }
}
