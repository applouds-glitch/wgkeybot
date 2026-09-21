package com.wireguard.android.util

import android.content.Context
import com.wireguard.android.R
import com.wireguard.android.backend.BackendException
import org.json.JSONException
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException

/** Shared by manual import and phone/TV deeplinks; never displays raw payloads. */
object ConnectionImportErrors {
    fun message(context: Context, error: Exception): String {
        if (error is ApiClient.HttpException) {
            return context.getString(R.string.wgk_import_http_error, error.statusCode)
        }
        if (error is BackendException) return ErrorMessages[error]
        val resource = when (error) {
            is ConnectionLink.InvalidLinkException -> when (error.reason) {
                ConnectionLink.Failure.EMPTY -> R.string.wgk_token_error_empty
                ConnectionLink.Failure.INVALID_FORMAT -> R.string.wgk_token_error_format
                ConnectionLink.Failure.MISSING_TOKEN -> R.string.wgk_deeplink_missing_token
                ConnectionLink.Failure.INVALID_DATA -> R.string.wgk_import_invalid_data
                ConnectionLink.Failure.UNSUPPORTED_VERSION -> R.string.wgk_import_unsupported_version
                ConnectionLink.Failure.INVALID_CONFIG -> R.string.wgk_import_invalid_config
                ConnectionLink.Failure.INVALID_SERVER_CONFIG -> R.string.wgk_server_bad_config
            }
            is ApiClient.InvalidTokenException -> R.string.wgk_token_error_format
            is ApiClient.UnauthorizedException -> R.string.wgk_import_unauthorized
            is ApiClient.UpgradeRequiredException -> R.string.wgk_import_upgrade_required
            is ConnectionImport.FetchException -> when (error.cause) {
                is SocketTimeoutException -> R.string.wgk_import_timeout
                is UnknownHostException -> R.string.wgk_import_dns_error
                is SSLException -> R.string.wgk_import_tls_error
                else -> R.string.wgk_import_network_error
            }
            is JSONException -> R.string.wgk_import_invalid_response
            is IOException -> R.string.wgk_import_storage_error
            else -> R.string.wgk_connection_import_error
        }
        return context.getString(resource)
    }
}
