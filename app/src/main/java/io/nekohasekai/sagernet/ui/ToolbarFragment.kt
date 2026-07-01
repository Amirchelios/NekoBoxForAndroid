package io.nekohasekai.sagernet.ui

import android.os.Bundle
import android.view.KeyEvent
import android.view.View
import androidx.appcompat.widget.Toolbar
import androidx.fragment.app.Fragment
import io.nekohasekai.sagernet.R

open class ToolbarFragment : Fragment {

    constructor() : super()
    constructor(contentLayoutId: Int) : super(contentLayoutId)

    private var _toolbar: Toolbar? = null
    val toolbar: Toolbar?
        get() = _toolbar

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _toolbar = view.findViewById(R.id.toolbar)
        _toolbar?.navigationIcon = null
        _toolbar?.setNavigationOnClickListener(null)
    }

    override fun onDestroyView() {
        _toolbar = null
        super.onDestroyView()
    }

    open fun onKeyDown(ketCode: Int, event: KeyEvent) = false
    open fun onBackPressed(): Boolean = false
}
