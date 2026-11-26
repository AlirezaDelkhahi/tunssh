package dev.tunssh.android

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import dev.tunssh.android.model.AppSettings
import dev.tunssh.android.model.AuthType
import dev.tunssh.android.model.CIDRRouteDTO
import dev.tunssh.android.model.ConnectConfigDTO
import dev.tunssh.android.model.ErrorDTO
import dev.tunssh.android.model.HostKeyPinDTO
import dev.tunssh.android.model.HostKeyPromptDTO
import dev.tunssh.android.model.LogEntryDTO
import dev.tunssh.android.model.Profile
import dev.tunssh.android.model.ProfileSecrets
import dev.tunssh.android.model.ShareHostKeyDTO
import dev.tunssh.android.model.ShareLinkMetaDTO
import dev.tunssh.android.model.ShareMode
import dev.tunssh.android.model.SharePayloadDTO
import dev.tunssh.android.model.StatusDTO
import dev.tunssh.android.model.TunnelState
import dev.tunssh.android.model.VPNPlanDTO
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ModelSerializationTest {

    @Test
    fun connectConfigRoundTripAndExactGoKeys() {
        val cfg = ConnectConfigDTO(
            profileId = "prof-1",
            host = "vps.example.com",
            port = 443,
            username = "root",
            authType = AuthType.KEY,
            password = "",
            privateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
            keyPassphrase = "key-pass",
            pinnedHostKey = HostKeyPinDTO(
                algorithm = "ssh-ed25519",
                sha256 = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
            ),
            bypassIranLan = true,
            enableIpv6 = false,
            upstreamDns = listOf("1.1.1.1", "8.8.8.8"),
        )

        val jsonObj = cfg.toJson()
        assertEquals("prof-1", jsonObj.getString("profile_id"))
        assertEquals("vps.example.com", jsonObj.getString("host"))
        assertEquals(443, jsonObj.getInt("port"))
        assertEquals("root", jsonObj.getString("username"))
        assertEquals("key", jsonObj.getString("auth_type"))
        assertEquals("", jsonObj.getString("password"))
        assertEquals(cfg.privateKey, jsonObj.getString("private_key"))
        assertEquals("key-pass", jsonObj.getString("key_passphrase"))
        assertTrue(jsonObj.getBoolean("bypass_iran_lan"))
        assertFalse(jsonObj.getBoolean("enable_ipv6"))
        val pinObj = jsonObj.getJSONObject("pinned_host_key")
        assertEquals("ssh-ed25519", pinObj.getString("algorithm"))
        assertEquals("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU", pinObj.getString("sha256"))
        val dnsArr = jsonObj.getJSONArray("upstream_dns")
        assertEquals(2, dnsArr.length())
        assertEquals("1.1.1.1", dnsArr.getString(0))
        assertEquals("8.8.8.8", dnsArr.getString(1))

        val parsed = ConnectConfigDTO.fromJsonString(cfg.toJsonString())
        assertEquals(cfg, parsed)
    }

    @Test
    fun connectConfigParsesNullPinnedHostKey() {
        val goJson = """
            {
              "profile_id": "p2",
              "host": "1.2.3.4",
              "port": 22,
              "username": "ubuntu",
              "auth_type": "password",
              "password": "pw",
              "private_key": "",
              "key_passphrase": "",
              "pinned_host_key": null,
              "bypass_iran_lan": false,
              "enable_ipv6": true,
              "upstream_dns": null
            }
        """.trimIndent()

        val parsed = ConnectConfigDTO.fromJsonString(goJson)
        assertEquals("p2", parsed.profileId)
        assertNull(parsed.pinnedHostKey)
        assertTrue(parsed.upstreamDns.isEmpty())
        assertFalse(parsed.bypassIranLan)
        assertTrue(parsed.enableIpv6)
    }

    @Test
    fun statusDtoWithoutAndWithLastError() {
        val goConnectedJson = """
            {
              "state": "connected",
              "profile_id": "p1",
              "attempt": 1,
              "rtt_ms": 48,
              "rx_bytes": 1048576,
              "tx_bytes": 524288,
              "rx_rate_bps": 12000,
              "tx_rate_bps": 4000,
              "connected_at_unix": 1700000000,
              "tun_attached": true,
              "bypass_iran_lan": true,
              "last_error": null
            }
        """.trimIndent()

        val connected = StatusDTO.fromJsonString(goConnectedJson)
        assertEquals(TunnelState.CONNECTED, connected.state)
        assertEquals("p1", connected.profileId)
        assertEquals(1, connected.attempt)
        assertEquals(48L, connected.rttMs)
        assertEquals(1048576L, connected.rxBytes)
        assertEquals(524288L, connected.txBytes)
        assertEquals(12000L, connected.rxRateBps)
        assertEquals(4000L, connected.txRateBps)
        assertEquals(1700000000L, connected.connectedAtUnix)
        assertTrue(connected.tunAttached)
        assertTrue(connected.bypassIranLan)
        assertNull(connected.lastError)

        val goErrorJson = """
            {
              "state": "error",
              "profile_id": "p1",
              "attempt": 3,
              "rtt_ms": 0,
              "rx_bytes": 0,
              "tx_bytes": 0,
              "rx_rate_bps": 0,
              "tx_rate_bps": 0,
              "connected_at_unix": 0,
              "tun_attached": false,
              "bypass_iran_lan": false,
              "last_error": {
                "code": "ERR_DPI_RESET",
                "message": "SSH handshake reset by peer",
                "action_hint": "Switch SSH port to 443 or 2053",
                "retryable": true
              }
            }
        """.trimIndent()

        val errStatus = StatusDTO.fromJsonString(goErrorJson)
        assertEquals(TunnelState.ERROR, errStatus.state)
        assertNotNull(errStatus.lastError)
        assertEquals("ERR_DPI_RESET", errStatus.lastError!!.code)
        assertEquals("SSH handshake reset by peer", errStatus.lastError!!.message)
        assertEquals("Switch SSH port to 443 or 2053", errStatus.lastError!!.actionHint)
        assertTrue(errStatus.lastError!!.retryable)
        assertEquals(errStatus, StatusDTO.fromJson(errStatus.toJson()))
    }

    @Test
    fun hostKeyPromptUntrustedAndMismatch() {
        val untrustedJson = """
            {
              "host": "example.org",
              "port": 22,
              "algorithm": "ssh-ed25519",
              "sha256": "SHA256:abc",
              "mismatch": false
            }
        """.trimIndent()

        val untrusted = HostKeyPromptDTO.fromJsonString(untrustedJson)
        assertEquals("example.org", untrusted.host)
        assertEquals(22, untrusted.port)
        assertEquals("ssh-ed25519", untrusted.algorithm)
        assertEquals("SHA256:abc", untrusted.sha256)
        assertFalse(untrusted.mismatch)
        assertEquals("", untrusted.expectedAlgorithm)
        assertEquals("", untrusted.expectedSha256)
        assertEquals(untrusted, HostKeyPromptDTO.fromJson(untrusted.toJson()))

        val mismatchJson = """
            {
              "host": "example.org",
              "port": 443,
              "algorithm": "ssh-rsa",
              "sha256": "SHA256:new",
              "mismatch": true,
              "expected_algorithm": "ssh-ed25519",
              "expected_sha256": "SHA256:old"
            }
        """.trimIndent()

        val mismatch = HostKeyPromptDTO.fromJsonString(mismatchJson)
        assertTrue(mismatch.mismatch)
        assertEquals("ssh-ed25519", mismatch.expectedAlgorithm)
        assertEquals("SHA256:old", mismatch.expectedSha256)
        assertEquals(mismatch, HostKeyPromptDTO.fromJson(mismatch.toJson()))
    }

    @Test
    fun vpnPlanIpv4OnlyAndIpv4PlusIpv6() {
        val ipv4OnlyJson = """
            {
              "tun_ipv4_addr": "198.18.0.1",
              "tun_ipv4_prefix": 15,
              "dns_ipv4": "198.18.0.2",
              "mtu": 1400,
              "routes": [
                {"address": "1.0.0.0", "prefix": 8},
                {"address": "8.8.8.8", "prefix": 32}
              ]
            }
        """.trimIndent()

        val ipv4Plan = VPNPlanDTO.fromJsonString(ipv4OnlyJson)
        assertEquals("198.18.0.1", ipv4Plan.tunIpv4Addr)
        assertEquals(15, ipv4Plan.tunIpv4Prefix)
        assertEquals("", ipv4Plan.tunIpv6Addr)
        assertEquals(0, ipv4Plan.tunIpv6Prefix)
        assertEquals("198.18.0.2", ipv4Plan.dnsIpv4)
        assertEquals(1400, ipv4Plan.mtu)
        assertEquals(2, ipv4Plan.routes.size)
        assertEquals(CIDRRouteDTO("1.0.0.0", 8), ipv4Plan.routes[0])
        assertEquals(ipv4Plan, VPNPlanDTO.fromJson(ipv4Plan.toJson()))

        val dualStackJson = """
            {
              "tun_ipv4_addr": "198.18.0.1",
              "tun_ipv4_prefix": 15,
              "tun_ipv6_addr": "fd00:198:18::1",
              "tun_ipv6_prefix": 64,
              "dns_ipv4": "198.18.0.2",
              "mtu": 1400,
              "routes": [
                {"address": "0.0.0.0", "prefix": 1},
                {"address": "::", "prefix": 1},
                {"address": "8000::", "prefix": 1}
              ]
            }
        """.trimIndent()

        val dualPlan = VPNPlanDTO.fromJsonString(dualStackJson)
        assertEquals("fd00:198:18::1", dualPlan.tunIpv6Addr)
        assertEquals(64, dualPlan.tunIpv6Prefix)
        assertEquals(3, dualPlan.routes.size)
        assertEquals(CIDRRouteDTO("8000::", 1), dualPlan.routes[2])
        assertEquals(dualPlan, VPNPlanDTO.fromJson(dualPlan.toJson()))
    }

    @Test
    fun logEntryAndArrayParsing() {
        val goLogsJson = """
            [
              {
                "timestamp": "2026-11-26T20:00:00Z",
                "level": "INFO",
                "message": "SSH tunnel connected"
              },
              {
                "timestamp": "2026-11-26T20:00:05Z",
                "level": "ERROR",
                "message": "SSH auth failed",
                "code": "ERR_AUTH_FAILED",
                "action_hint": "Verify username and password"
              }
            ]
        """.trimIndent()

        val logs = LogEntryDTO.listFromJsonArrayString(goLogsJson)
        assertEquals(2, logs.size)
        assertEquals("INFO", logs[0].level)
        assertEquals("", logs[0].code)
        assertEquals("ERROR", logs[1].level)
        assertEquals("ERR_AUTH_FAILED", logs[1].code)
        assertEquals("Verify username and password", logs[1].actionHint)
        assertEquals(logs[1], LogEntryDTO.fromJson(logs[1].toJson()))
    }

    @Test
    fun shareLinkMetaAndPayloadSerialization() {
        val metaJson = """{"version":1,"mode":"enc","has_host_key":true}"""
        val meta = ShareLinkMetaDTO.fromJsonString(metaJson)
        assertEquals(1, meta.version)
        assertEquals(ShareMode.ENCRYPTED, meta.mode)
        assertTrue(meta.hasHostKey)
        assertEquals(meta, ShareLinkMetaDTO.fromJson(meta.toJson()))

        val payload = SharePayloadDTO(
            name = "Germany VPS",
            host = "de.example.com",
            port = 443,
            user = "tunnel",
            authType = AuthType.KEY,
            secret = "PEM-CONTENT",
            keyPassphrase = "pass",
            hostKey = ShareHostKeyDTO(alg = "ssh-ed25519", sha256 = "SHA256:xyz"),
            mode = ShareMode.ENCRYPTED,
        )
        val rawObj = JSONObject(payload.toJsonString())
        assertEquals("Germany VPS", rawObj.getString("name"))
        assertEquals("de.example.com", rawObj.getString("host"))
        assertEquals(443, rawObj.getInt("port"))
        assertEquals("tunnel", rawObj.getString("user"))
        assertEquals("key", rawObj.getString("auth_type"))
        assertEquals("PEM-CONTENT", rawObj.getString("secret"))
        assertEquals("pass", rawObj.getString("key_passphrase"))
        assertEquals("enc", rawObj.getString("mode"))
        assertEquals("ssh-ed25519", rawObj.getJSONObject("host_key").getString("alg"))
        assertEquals("SHA256:xyz", rawObj.getJSONObject("host_key").getString("sha256"))

        assertEquals(payload, SharePayloadDTO.fromJsonString(payload.toJsonString()))
    }

    @Test
    fun profileToJsonNeverSerializesSecrets() {
        val profile = Profile(
            id = "id-123",
            name = "Primary",
            host = "198.51.100.10",
            port = 22,
            username = "admin",
            authType = AuthType.PASSWORD,
            bypassIranLan = true,
            pinnedHostKey = HostKeyPinDTO("ssh-ed25519", "SHA256:pinned"),
            createdAtUnix = 1700000000L,
            updatedAtUnix = 1700000100L,
        )

        val json = profile.toJson()
        assertFalse(json.has("password"))
        assertFalse(json.has("private_key"))
        assertFalse(json.has("privateKey"))
        assertFalse(json.has("key_passphrase"))
        assertFalse(json.has("keyPassphrase"))
        assertFalse(json.has("secret"))

        val roundTrip = Profile.fromJson(json)
        assertEquals(profile, roundTrip)
    }

    @Test
    fun profileSecretsAndAppSettingsRoundTrip() {
        val secrets = ProfileSecrets(
            password = "super-secret-password",
            privateKey = "private-key-pem",
            keyPassphrase = "key-passphrase",
        )
        assertEquals(secrets, ProfileSecrets.fromJsonString(secrets.toJsonString()))

        val settings = AppSettings(
            selectedProfileId = "prof-1",
            enableIpv6 = false,
            disallowedPackages = setOf("ir.bank.app", "com.example.local"),
            batteryBannerDismissed = true,
        )
        val parsedSettings = AppSettings.fromJson(settings.toJson())
        assertEquals(settings, parsedSettings)
    }

    @Test
    fun qrCodeEncodeAndDecodeRoundTripOnJvm() {
        val sampleUri = "sshtun://v1/eyJ2IjoxLCJtIjoiZW5jIiwia2RmIjoiYXJnb24yaWQiLCJzYWx0IjoiQUFBQSJ9"
        val encodeHints = mapOf(
            EncodeHintType.CHARACTER_SET to "UTF-8",
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            EncodeHintType.MARGIN to 2,
        )
        val matrix = QRCodeWriter().encode(sampleUri, BarcodeFormat.QR_CODE, 256, 256, encodeHints)
        val width = matrix.width
        val height = matrix.height
        val luma = ByteArray(width * height)
        for (y in 0 until height) {
            val rowOffset = y * width
            for (x in 0 until width) {
                luma[rowOffset + x] = if (matrix.get(x, y)) 0x00 else 0xFF.toByte()
            }
        }

        val source = PlanarYUVLuminanceSource(luma, width, height, 0, 0, width, height, false)
        val decodeHints = mapOf(
            DecodeHintType.CHARACTER_SET to "UTF-8",
            DecodeHintType.TRY_HARDER to true,
        )
        val reader = QRCodeReader()
        val decoded = try {
            reader.decode(BinaryBitmap(HybridBinarizer(source)), decodeHints)
        } finally {
            reader.reset()
        }
        assertEquals(sampleUri, decoded.text)
    }
}
