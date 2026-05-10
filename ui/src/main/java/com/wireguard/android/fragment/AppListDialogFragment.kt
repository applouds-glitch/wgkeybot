/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.Manifest
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PackageManager.PackageInfoFlags
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.os.bundleOf
import androidx.databinding.Observable
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.setFragmentResult
import androidx.lifecycle.lifecycleScope
import com.google.android.material.tabs.TabLayout
import com.wireguard.android.BR
import com.wireguard.android.R
import com.wireguard.android.databinding.AppListDialogFragmentBinding
import com.wireguard.android.databinding.ObservableKeyedArrayList
import com.wireguard.android.model.ApplicationData
import com.wireguard.android.util.ErrorMessages
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AppListDialogFragment : DialogFragment() {
    private val appData = ObservableKeyedArrayList<String, ApplicationData>()
    private var currentlySelectedApps = emptyList<String>()
    private var initiallyExcluded = false
    private var binding: AppListDialogFragmentBinding? = null
    private val allAppData = mutableListOf<ApplicationData>()
    private var showSystemApps = false
    private var lastQuery = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setStyle(STYLE_NORMAL, R.style.Theme_WGKeyBot_FullScreen)
        currentlySelectedApps = (arguments?.getStringArrayList(KEY_SELECTED_APPS) ?: emptyList())
        initiallyExcluded = arguments?.getBoolean(KEY_IS_EXCLUDED) ?: false
    }

    override fun onStart() {
        super.onStart()
        dialog?.window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        val b = AppListDialogFragmentBinding.inflate(inflater, container, false)
        binding = b
        b.appData = appData

        b.tabs.selectTab(b.tabs.getTabAt(if (initiallyExcluded) 0 else 1))
        updateInfoBanner()

        b.tabs.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabReselected(tab: TabLayout.Tab?) = Unit
            override fun onTabUnselected(tab: TabLayout.Tab?) = Unit
            override fun onTabSelected(tab: TabLayout.Tab?) {
                updateInfoBanner()
                updateButtons()
            }
        })

        b.searchInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                lastQuery = s?.toString() ?: ""
                applyFilter()
                updateButtons()
            }
        })

        b.showSystemAppsCheckbox.setOnCheckedChangeListener { _, isChecked ->
            showSystemApps = isChecked
            applyFilter()
            updateButtons()
        }

        b.btnBack.setOnClickListener { dismissAllowingStateLoss() }

        b.btnFilter.setOnClickListener {
            val row = b.systemAppsRow
            val divider = b.systemAppsDivider
            if (row.visibility == View.GONE) {
                row.visibility = View.VISIBLE
                divider.visibility = View.VISIBLE
            } else {
                row.visibility = View.GONE
                divider.visibility = View.GONE
                if (showSystemApps) {
                    showSystemApps = false
                    b.showSystemAppsCheckbox.isChecked = false
                    applyFilter()
                    updateButtons()
                }
            }
        }

        b.btnToggleAll.setOnClickListener {
            val selectAll = allAppData.none { it.isSelected }
            allAppData.forEach { it.isSelected = selectAll }
            updateButtons()
        }

        b.btnCancel.setOnClickListener { dismissAllowingStateLoss() }
        b.btnApply.setOnClickListener { setSelectionAndDismiss() }

        loadData()
        return b.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        binding = null
    }

    private fun loadData() {
        val activity = activity ?: return
        val pm = activity.packageManager
        lifecycleScope.launch(Dispatchers.Default) {
            try {
                val applicationData: MutableList<ApplicationData> = ArrayList()
                withContext(Dispatchers.IO) {
                    val packageInfos = getPackagesHoldingPermissions(pm, arrayOf(Manifest.permission.INTERNET))
                    packageInfos.forEach {
                        val packageName = it.packageName
                        val appInfo = it.applicationInfo ?: return@forEach
                        val isSystem = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0 &&
                                (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
                        val data = ApplicationData(
                            appInfo.loadIcon(pm), appInfo.loadLabel(pm).toString(),
                            packageName, currentlySelectedApps.contains(packageName), isSystem
                        )
                        applicationData.add(data)
                        data.addOnPropertyChangedCallback(object : Observable.OnPropertyChangedCallback() {
                            override fun onPropertyChanged(sender: Observable?, propertyId: Int) {
                                if (propertyId == BR.selected) updateButtons()
                            }
                        })
                    }
                }
                applicationData.sortWith(
                    compareByDescending<ApplicationData> { it.isSelected }
                        .thenBy(String.CASE_INSENSITIVE_ORDER) { it.name }
                )
                withContext(Dispatchers.Main.immediate) {
                    allAppData.clear()
                    allAppData.addAll(applicationData)
                    applyFilter()
                    updateButtons()
                }
            } catch (e: Throwable) {
                withContext(Dispatchers.Main.immediate) {
                    val error = ErrorMessages[e]
                    val message = activity.getString(R.string.error_fetching_apps, error)
                    Toast.makeText(activity, message, Toast.LENGTH_LONG).show()
                    dismissAllowingStateLoss()
                }
            }
        }
    }

    private fun getPackagesHoldingPermissions(pm: PackageManager, permissions: Array<String>): List<PackageInfo> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackagesHoldingPermissions(permissions, PackageInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackagesHoldingPermissions(permissions, 0)
        }
    }

    private fun applyFilter() {
        val q = lastQuery.trim().lowercase()
        appData.clear()
        appData.addAll(allAppData.filter { app ->
            (showSystemApps || !app.isSystem) &&
                    (q.isEmpty() || app.name.lowercase().contains(q) || app.packageName.lowercase().contains(q))
        })
    }

    private fun updateInfoBanner() {
        val b = binding ?: return
        val tabPos = b.tabs.selectedTabPosition
        b.infoText.text = getString(
            if (tabPos == 0) R.string.wgk_split_exclude_hint else R.string.wgk_split_include_hint
        )
    }

    private fun updateButtons() {
        val b = binding ?: return
        val numSelected = allAppData.count { it.isSelected }
        val total = allAppData.size

        b.subtitleText.text = if (total > 0)
            getString(R.string.wgk_split_selected_of, numSelected, total)
        else
            ""

        b.btnApply.text = if (numSelected == 0)
            getString(R.string.wgk_split_apply)
        else
            getString(R.string.wgk_split_apply_n, numSelected)
    }

    private fun setSelectionAndDismiss() {
        val b = binding ?: return
        val selectedApps = allAppData.filter { it.isSelected }.map { it.packageName }
        setFragmentResult(
            REQUEST_SELECTION, bundleOf(
                KEY_SELECTED_APPS to selectedApps.toTypedArray(),
                KEY_IS_EXCLUDED to (b.tabs.selectedTabPosition == 0)
            )
        )
        dismiss()
    }

    companion object {
        const val KEY_SELECTED_APPS = "selected_apps"
        const val KEY_IS_EXCLUDED = "is_excluded"
        const val REQUEST_SELECTION = "request_selection"

        fun newInstance(selectedApps: ArrayList<String?>?, isExcluded: Boolean): AppListDialogFragment {
            val extras = Bundle()
            extras.putStringArrayList(KEY_SELECTED_APPS, selectedApps)
            extras.putBoolean(KEY_IS_EXCLUDED, isExcluded)
            val fragment = AppListDialogFragment()
            fragment.arguments = extras
            return fragment
        }
    }
}
