package io.nekohasekai.sagernet.ui

import android.animation.AnimatorSet
import android.animation.ArgbEvaluator
import android.animation.ObjectAnimator
import android.animation.PropertyValuesHolder
import android.animation.ValueAnimator
import android.graphics.drawable.GradientDrawable
import android.view.View
import androidx.core.content.ContextCompat
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.bg.BaseService
import io.nekohasekai.sagernet.databinding.LayoutMainBinding

class MainActivityConnectionAnimator(
    private val activity: MainActivity,
    private val binding: LayoutMainBinding,
) {
    private var glowAnimator: ObjectAnimator? = null
    private var stateAnimator: ObjectAnimator? = null
    private var connectAnimator: AnimatorSet? = null
    private var ringAnimator: AnimatorSet? = null
    private var fabColorAnimator: ValueAnimator? = null
    private var ringSoftAnimator: AnimatorSet? = null
    private var ambientAnimator: ObjectAnimator? = null
    private var disconnectCollapseAnimator: AnimatorSet? = null
    private var currentState: BaseService.State? = null
    private var stateVersion = 0L
    var disconnectAnimating = false
        private set

    fun updateGlow(state: BaseService.State) {
        val glow = binding.connectGlow
        if (state == BaseService.State.Connected) {
            if (glowAnimator?.isRunning == true) return
            glow.visibility = View.VISIBLE
            glowAnimator?.cancel()
            glowAnimator = ObjectAnimator.ofPropertyValuesHolder(
                glow,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.35f, 0.15f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.08f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.08f)
            ).apply {
                duration = 1400L
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
                start()
            }
        } else if (state == BaseService.State.Connecting) {
            glowAnimator?.cancel()
            glowAnimator = null
        } else {
            glowAnimator?.cancel()
            glowAnimator = null
            glow.alpha = 0f
            glow.scaleX = 1f
            glow.scaleY = 1f
            glow.visibility = View.INVISIBLE
        }
    }

    fun updateConnectAnimation(state: BaseService.State) {
        stateVersion++
        val version = stateVersion
        cancelLoopingAnimators()
        if (state != BaseService.State.Stopping) {
            cancelDisconnectCollapse()
        }

        if (state == BaseService.State.Connecting) {
            val density = activity.resources.displayMetrics.density
            val fab = binding.fab
            val glow = binding.connectGlow
            val ring = binding.connectRing
            val ringSoft = binding.connectRingSoft
            val ambient = binding.connectAmbient
            fab.translationY = 0f
            val baseFabY = 0f

            glow.visibility = View.VISIBLE
            glow.alpha = 0.2f
            glow.scaleX = 1f
            glow.scaleY = 1f

            ambient.visibility = View.VISIBLE
            ambient.alpha = 0.18f
            ambient.scaleX = 1f
            ambient.scaleY = 1f

            ring.visibility = View.VISIBLE
            ring.alpha = 0f
            ring.scaleX = 0.9f
            ring.scaleY = 0.9f

            ringSoft.visibility = View.VISIBLE
            ringSoft.alpha = 0f
            ringSoft.scaleX = 0.92f
            ringSoft.scaleY = 0.92f

            val glowPulse = ObjectAnimator.ofPropertyValuesHolder(
                glow,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.25f, 0.12f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.12f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.12f)
            ).apply {
                duration = 900L
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
            }

            val fabBreath = ObjectAnimator.ofPropertyValuesHolder(
                fab,
                PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.05f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.05f)
            ).apply {
                duration = 700L
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
            }

            val fabFloat = ObjectAnimator.ofFloat(
                fab,
                View.TRANSLATION_Y,
                baseFabY,
                baseFabY - (6f * density),
                baseFabY
            ).apply {
                duration = 1200L
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
                addUpdateListener { activity.updateConnectEffectOffsets() }
            }

            connectAnimator = AnimatorSet().apply {
                playTogether(glowPulse, fabBreath, fabFloat)
                start()
            }

            val ringExpand = ObjectAnimator.ofPropertyValuesHolder(
                ring,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.0f, 0.22f, 0.0f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 0.86f, 1.18f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 0.86f, 1.18f)
            ).apply {
                duration = 2000L
                repeatCount = ValueAnimator.INFINITE
                repeatMode = ValueAnimator.RESTART
            }
            ringAnimator = AnimatorSet().apply {
                playTogether(ringExpand)
                start()
            }

            val ringSoftExpand = ObjectAnimator.ofPropertyValuesHolder(
                ringSoft,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.0f, 0.14f, 0.0f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 0.9f, 1.26f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 0.9f, 1.26f)
            ).apply {
                duration = 2600L
                startDelay = 320L
                repeatCount = ValueAnimator.INFINITE
                repeatMode = ValueAnimator.RESTART
            }
            ringSoftAnimator = AnimatorSet().apply {
                playTogether(ringSoftExpand)
                start()
            }

            setRingStrokeColor(
                ContextCompat.getColor(activity, R.color.connect_ring),
                ContextCompat.getColor(activity, R.color.connect_ring)
            )

            ambientAnimator = ObjectAnimator.ofPropertyValuesHolder(
                ambient,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.12f, 0.28f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.05f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.05f)
            ).apply {
                duration = 1600L
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
                start()
            }

            animateFabColor(
                ContextCompat.getColor(activity, R.color.connect_fab_background),
                ContextCompat.getColor(activity, R.color.connect_fab_background_connecting)
            )
        } else if (state == BaseService.State.Connected) {
            val ring = binding.connectRing
            val ringSoft = binding.connectRingSoft
            val ambient = binding.connectAmbient

            ring.visibility = View.VISIBLE
            ring.alpha = 0f
            ring.scaleX = 0.95f
            ring.scaleY = 0.95f

            ringSoft.visibility = View.VISIBLE
            ringSoft.alpha = 0f
            ringSoft.scaleX = 0.96f
            ringSoft.scaleY = 0.96f

            setRingStrokeColor(
                ContextCompat.getColor(activity, R.color.connect_ring_connected),
                ContextCompat.getColor(activity, R.color.connect_ring_connected)
            )

            val ringExpand = ObjectAnimator.ofPropertyValuesHolder(
                ring,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.0f, 0.18f, 0.0f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 0.9f, 1.2f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 0.9f, 1.2f)
            ).apply {
                duration = 2400L
                repeatCount = ValueAnimator.INFINITE
                repeatMode = ValueAnimator.RESTART
            }
            ringAnimator = AnimatorSet().apply {
                playTogether(ringExpand)
                start()
            }

            val ringSoftExpand = ObjectAnimator.ofPropertyValuesHolder(
                ringSoft,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.0f, 0.12f, 0.0f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 0.92f, 1.26f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 0.92f, 1.26f)
            ).apply {
                duration = 3200L
                startDelay = 360L
                repeatCount = ValueAnimator.INFINITE
                repeatMode = ValueAnimator.RESTART
            }
            ringSoftAnimator = AnimatorSet().apply {
                playTogether(ringSoftExpand)
                start()
            }

            ambient.visibility = View.VISIBLE
            ambient.alpha = 0.18f
            ambientAnimator = ObjectAnimator.ofPropertyValuesHolder(
                ambient,
                PropertyValuesHolder.ofFloat(View.ALPHA, 0.12f, 0.22f),
                PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.03f),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.03f)
            ).apply {
                duration = 2200L
                repeatMode = ValueAnimator.REVERSE
                repeatCount = ValueAnimator.INFINITE
                start()
            }

            animateFabColor(
                ContextCompat.getColor(activity, R.color.connect_fab_background_connecting),
                ContextCompat.getColor(activity, R.color.connect_fab_background_connected)
            )
        } else {
            val ring = binding.connectRing
            val ringSoft = binding.connectRingSoft
            val ambient = binding.connectAmbient
            if (!disconnectAnimating) {
                ring.visibility = View.INVISIBLE
                ring.alpha = 0f
                ring.scaleX = 1f
                ring.scaleY = 1f
                ringSoft.visibility = View.INVISIBLE
                ringSoft.alpha = 0f
                ringSoft.scaleX = 1f
                ringSoft.scaleY = 1f
            }
            binding.fab.scaleX = 1f
            binding.fab.scaleY = 1f
            binding.fab.translationY = 0f
            activity.updateConnectEffectOffsets()

            when (state) {
                BaseService.State.Stopping -> animateFabColor(
                    ContextCompat.getColor(activity, R.color.connect_fab_background_connected),
                    ContextCompat.getColor(activity, R.color.connect_fab_background_stopping),
                    800L
                )
                else -> animateFabColor(
                    ContextCompat.getColor(activity, R.color.connect_fab_background_connected),
                    ContextCompat.getColor(activity, R.color.connect_fab_background)
                )
            }

            when (state) {
                BaseService.State.Stopping -> playDisconnectCollapse(version)
                else -> {
                    if (!disconnectAnimating) {
                        ambient.visibility = View.INVISIBLE
                        ambient.alpha = 0f
                    }
                }
            }
        }
    }

    private fun cancelLoopingAnimators() {
        connectAnimator?.cancel()
        connectAnimator = null
        ringAnimator?.cancel()
        ringAnimator = null
        ringSoftAnimator?.cancel()
        ringSoftAnimator = null
        ambientAnimator?.cancel()
        ambientAnimator = null
        fabColorAnimator?.cancel()
        fabColorAnimator = null
        glowAnimator?.cancel()
        glowAnimator = null
        binding.fab.animate().cancel()
    }

    private fun animateFabColor(fromColor: Int, toColor: Int, durationMs: Long = 420L) {
        fabColorAnimator?.cancel()
        fabColorAnimator = ValueAnimator.ofObject(ArgbEvaluator(), fromColor, toColor).apply {
            duration = durationMs
            addUpdateListener { animator ->
                val color = animator.animatedValue as Int
                binding.fab.backgroundTintList =
                    android.content.res.ColorStateList.valueOf(color)
            }
            start()
        }
    }

    private fun cancelDisconnectCollapse() {
        disconnectCollapseAnimator?.cancel()
        disconnectCollapseAnimator = null
        disconnectAnimating = false
    }

    private fun playDisconnectCollapse(version: Long) {
        if (disconnectAnimating) return
        disconnectAnimating = true
        val ring = binding.connectRing
        val ringSoft = binding.connectRingSoft
        val ambient = binding.connectAmbient

        ring.visibility = View.VISIBLE
        ring.alpha = 0.26f
        ring.scaleX = 1.08f
        ring.scaleY = 1.08f

        ringSoft.visibility = View.VISIBLE
        ringSoft.alpha = 0.16f
        ringSoft.scaleX = 1.12f
        ringSoft.scaleY = 1.12f

        setRingStrokeColor(
            ContextCompat.getColor(activity, R.color.connect_ring_disconnect),
            ContextCompat.getColor(activity, R.color.connect_ring_disconnect)
        )

        val ringOut = ObjectAnimator.ofPropertyValuesHolder(
            ring,
            PropertyValuesHolder.ofFloat(View.ALPHA, 0.26f, 0f),
            PropertyValuesHolder.ofFloat(View.SCALE_X, 1.08f, 0.88f),
            PropertyValuesHolder.ofFloat(View.SCALE_Y, 1.08f, 0.88f)
        ).apply { duration = 3000L }

        val ringSoftOut = ObjectAnimator.ofPropertyValuesHolder(
            ringSoft,
            PropertyValuesHolder.ofFloat(View.ALPHA, 0.16f, 0f),
            PropertyValuesHolder.ofFloat(View.SCALE_X, 1.12f, 0.9f),
            PropertyValuesHolder.ofFloat(View.SCALE_Y, 1.12f, 0.9f)
        ).apply { duration = 3000L }

        val ambientFade = ObjectAnimator.ofFloat(ambient, View.ALPHA, ambient.alpha, 0f).apply {
            duration = 3000L
        }

        disconnectCollapseAnimator = AnimatorSet().apply {
            playTogether(ringOut, ringSoftOut, ambientFade)
            addListener(object : android.animation.AnimatorListenerAdapter() {
                override fun onAnimationCancel(animation: android.animation.Animator) {
                    disconnectAnimating = false
                }

                override fun onAnimationEnd(animation: android.animation.Animator) {
                    if (version != stateVersion) return
                    ring.visibility = View.INVISIBLE
                    ringSoft.visibility = View.INVISIBLE
                    ambient.visibility = View.INVISIBLE
                    disconnectAnimating = false
                    disconnectCollapseAnimator = null
                }
            })
            start()
        }
    }

    private fun setRingStrokeColor(ringColor: Int, ringSoftColor: Int) {
        val ring = binding.connectRing.background as? GradientDrawable
        val ringSoft = binding.connectRingSoft.background as? GradientDrawable
        val density = activity.resources.displayMetrics.density
        val ringStroke = (2f * density).toInt()
        val ringSoftStroke = (1f * density).toInt()
        ring?.setStroke(ringStroke, ringColor)
        ringSoft?.setStroke(ringSoftStroke, ringSoftColor)
    }

    fun updateStateAnimation(state: BaseService.State) {
        if (currentState == state && state != BaseService.State.Connecting) return
        currentState = state
        stateAnimator?.cancel()
        stateAnimator = null
        if (state != BaseService.State.Connecting) {
            binding.fragmentHolder.scaleX = 1f
            binding.fragmentHolder.scaleY = 1f
        }
        if (state != BaseService.State.Stopping) {
            binding.fragmentHolder.alpha = 1f
        }
        when (state) {
            BaseService.State.Connecting -> {
                stateAnimator = ObjectAnimator.ofPropertyValuesHolder(
                    binding.fragmentHolder,
                    PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.01f),
                    PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.01f)
                ).apply {
                    duration = 1200L
                    repeatMode = ValueAnimator.REVERSE
                    repeatCount = ValueAnimator.INFINITE
                    start()
                }
            }
            BaseService.State.Stopping -> {
                val fab = binding.fab
                fab.animate().cancel()
                stateAnimator = ObjectAnimator.ofPropertyValuesHolder(
                    binding.fragmentHolder,
                    PropertyValuesHolder.ofFloat(View.ALPHA, 1f, 0.9f, 1f)
                ).apply {
                    duration = 360L
                    repeatCount = 0
                    start()
                }
                fab.animate()
            }
            else -> Unit
        }
        updateConnectAnimation(state)
        updateGlow(state)
    }

    fun release() {
        currentState = null
        stateVersion++
        cancelLoopingAnimators()
        cancelDisconnectCollapse()
        glowAnimator?.cancel()
        glowAnimator = null
        stateAnimator?.cancel()
        stateAnimator = null
    }
}
