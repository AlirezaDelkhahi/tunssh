package dev.tunssh.android.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.tunssh.android.model.LogEntryDTO
import dev.tunssh.android.ui.FormatUtils
import dev.tunssh.android.ui.theme.TunSshColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogSheet(
    logs: List<LogEntryDTO>,
    onExportText: () -> String,
    onClear: () -> Unit,
    onCopied: () -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val clipboard = LocalClipboardManager.current

    var filterLevel by remember { mutableStateOf("ALL") }
    var searchQuery by remember { mutableStateOf("") }

    val filtered = remember(logs, filterLevel, searchQuery) {
        val q = searchQuery.trim().lowercase()
        logs.asReversed().filter { entry ->
            val levelOk = when (filterLevel) {
                "WARN_ERR" -> entry.level == "WARN" || entry.level == "ERROR"
                "ERROR" -> entry.level == "ERROR"
                else -> true
            }
            val queryOk = q.isEmpty() ||
                entry.message.lowercase().contains(q) ||
                entry.code.lowercase().contains(q) ||
                entry.actionHint.lowercase().contains(q)
            levelOk && queryOk
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = TunSshColors.BgSurface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.85f)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column {
                    Text(
                        text = "Diagnostic Logs",
                        style = MaterialTheme.typography.titleMedium,
                        color = TunSshColors.TextPrimary,
                    )
                    Text(
                        text = "Redacted in Go • ${filtered.size} / ${logs.size} entries",
                        style = MaterialTheme.typography.bodySmall,
                        color = TunSshColors.TextMuted,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = {
                            clipboard.setText(AnnotatedString(onExportText()))
                            onCopied()
                        },
                        enabled = logs.isNotEmpty(),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.ContentCopy,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Copy All")
                    }
                    TextButton(
                        onClick = onClear,
                        enabled = logs.isNotEmpty(),
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Delete,
                            contentDescription = null,
                            tint = TunSshColors.WarningAmber,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Clear", color = TunSshColors.WarningAmber)
                    }
                }
            }

            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Search logs or error codes...") },
                leadingIcon = {
                    Icon(imageVector = Icons.Rounded.Search, contentDescription = null)
                },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = filterLevel == "ALL",
                    onClick = { filterLevel = "ALL" },
                    label = { Text("All") },
                )
                FilterChip(
                    selected = filterLevel == "WARN_ERR",
                    onClick = { filterLevel = "WARN_ERR" },
                    label = { Text("Warn / Err") },
                )
                FilterChip(
                    selected = filterLevel == "ERROR",
                    onClick = { filterLevel = "ERROR" },
                    label = { Text("Errors") },
                )
            }

            if (filtered.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "No matching redacted log entries.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TunSshColors.TextSubtle,
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    items(filtered) { entry ->
                        val levelColor = when (entry.level) {
                            "ERROR" -> TunSshColors.ErrorRed
                            "WARN" -> TunSshColors.WarningAmber
                            "DEBUG" -> TunSshColors.TextSubtle
                            else -> TunSshColors.AccentBlue
                        }
                        Surface(
                            color = TunSshColors.BgInset,
                            shape = RoundedCornerShape(8.dp),
                            border = BorderStroke(1.dp, TunSshColors.BorderSubtle),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Column(
                                modifier = Modifier.padding(10.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Row(
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Text(
                                        text = FormatUtils.formatLogTime(entry.timestamp),
                                        style = MaterialTheme.typography.bodySmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                        ),
                                        color = TunSshColors.TextSubtle,
                                    )
                                    Text(
                                        text = entry.level,
                                        style = MaterialTheme.typography.labelMedium,
                                        color = levelColor,
                                    )
                                    if (entry.code.isNotEmpty()) {
                                        Text(
                                            text = entry.code,
                                            style = MaterialTheme.typography.labelMedium.copy(
                                                fontFamily = FontFamily.Monospace,
                                            ),
                                            color = TunSshColors.WarningAmber,
                                        )
                                    }
                                }
                                Text(
                                    text = entry.message,
                                    style = MaterialTheme.typography.bodySmall.copy(
                                        fontFamily = FontFamily.Monospace,
                                    ),
                                    color = TunSshColors.TextPrimary,
                                )
                                if (entry.actionHint.isNotEmpty()) {
                                    Text(
                                        text = "Hint: ${entry.actionHint}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = TunSshColors.TextMuted,
                                    )
                                }
                            }
                        }
                    }
                    item { Spacer(modifier = Modifier.height(16.dp)) }
                }
            }
        }
    }
}
