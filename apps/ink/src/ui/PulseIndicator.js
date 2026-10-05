import React, { useState, useEffect, memo } from 'react';
import { Text } from 'ink';

const FRAMES_DOTS = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const FRAMES_PULSE = ['●', '◐', '◓', '◑', '◒'];
const FRAMES_CALM = ['·', '•', '●', '•'];

/**
 * Isolated, zero-flicker pulse indicator component.
 * Renders in a dedicated memoized leaf node to completely prevent parent re-renders.
 */
export const PulseIndicator = memo(function PulseIndicator({
  type = 'dots',
  color = 'yellow',
  intervalMs = 280,
  staticChar = null
}) {
  const [frameIdx, setFrameIdx] = useState(0);

  useEffect(() => {
    if (staticChar) return;
    const timer = setInterval(() => {
      setFrameIdx((prev) => (prev + 1) % (type === 'pulse' ? FRAMES_PULSE.length : type === 'calm' ? FRAMES_CALM.length : FRAMES_DOTS.length));
    }, intervalMs);
    return () => clearInterval(timer);
  }, [type, intervalMs, staticChar]);

  if (staticChar) {
    return React.createElement(Text, { color, bold: true }, staticChar);
  }

  const frames = type === 'pulse' ? FRAMES_PULSE : type === 'calm' ? FRAMES_CALM : FRAMES_DOTS;
  const char = frames[frameIdx % frames.length];

  return React.createElement(Text, { color, bold: true }, char);
});

/**
 * Drop-in replacement for ink-spinner that does not trigger parent layout churn
 */
export const FlickerFreeSpinner = memo(function FlickerFreeSpinner({
  type = 'dots',
  color = 'yellow',
  intervalMs = 250
}) {
  return React.createElement(PulseIndicator, { type, color, intervalMs });
});

export default FlickerFreeSpinner;
