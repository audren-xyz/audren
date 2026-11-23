"use client";

import type { CSSProperties } from "react";
import { Pause, Play } from "lucide-react";
import m from "./motion.module.css";

interface SceneControlsProps {
  /** Short label per step, shown under its progress track. */
  steps: readonly string[];
  step: number;
  playing: boolean;
  running: boolean;
  duration: number;
  /** `cycle` from useAutoStepper; restarts the current progress track. */
  cycle: string;
  onSelect: (idx: number) => void;
  onTogglePlay: () => void;
  /** Accessible name of the step list, e.g. "Private payment steps". */
  label: string;
  tone?: "light" | "dark";
}

/**
 * Play/pause + one button per step with a hairline progress track.
 * The current track fills over the step's duration while the scene runs.
 */
export function SceneControls({
  steps,
  step,
  playing,
  running,
  duration,
  cycle,
  onSelect,
  onTogglePlay,
  label,
  tone = "light",
}: SceneControlsProps) {
  return (
    <div className={m.controls} data-tone={tone}>
      <button
        type="button"
        className={m.playBtn}
        onClick={onTogglePlay}
        aria-label={playing ? "Pause walkthrough" : "Play walkthrough"}
      >
        {playing ? (
          <Pause size={13} aria-hidden="true" />
        ) : (
          <Play size={13} aria-hidden="true" />
        )}
      </button>
      <ol className={m.stepList} aria-label={label}>
        {steps.map((text, idx) => (
          <li key={text}>
            <StepButton
              idx={idx}
              step={step}
              text={text}
              playing={playing}
              running={running}
              duration={duration}
              cycle={cycle}
              onSelect={onSelect}
            />
          </li>
        ))}
      </ol>
    </div>
  );
}

interface StepButtonProps {
  idx: number;
  step: number;
  text: string;
  playing: boolean;
  running: boolean;
  duration: number;
  cycle: string;
  onSelect: (idx: number) => void;
  className?: string;
  children?: React.ReactNode;
}

/** A step button with a progress track; reused by scenes with richer step cards. */
export function StepButton({
  idx,
  step,
  text,
  playing,
  running,
  duration,
  cycle,
  onSelect,
  className,
  children,
}: StepButtonProps) {
  const state = idx < step ? "done" : idx === step ? "current" : "todo";
  return (
    <button
      type="button"
      className={`${m.stepBtn} ${className ?? ""}`}
      data-state={state}
      aria-current={state === "current" ? "step" : undefined}
      onClick={() => onSelect(idx)}
    >
      <ProgressTrack
        state={state}
        animate={state === "current" && playing}
        running={running}
        duration={duration}
        resetKey={`${cycle}-${playing}`}
      />
      {children ?? (
        <span className={m.stepText}>
          <span className={m.stepNum}>{idx + 1}</span>
          <span className={m.stepLabel}>{text}</span>
        </span>
      )}
    </button>
  );
}

export function ProgressTrack({
  state,
  animate,
  running,
  duration,
  resetKey,
}: {
  state: "done" | "current" | "todo";
  animate: boolean;
  running: boolean;
  duration: number;
  resetKey: string;
}) {
  return (
    <span className={m.track} aria-hidden="true">
      <span
        key={state === "current" ? resetKey : state}
        className={m.trackFill}
        data-state={state}
        data-animate={animate ? "on" : "off"}
        style={
          {
            "--dur": `${duration}ms`,
            animationPlayState: running ? "running" : "paused",
          } as CSSProperties
        }
      />
    </span>
  );
}

/**
 * One plain-language caption per step. Every caption is laid out in the same
 * grid cell, so the block is exactly as tall as its longest sentence: no jump
 * between steps and no oversized gap under short ones.
 */
export function SceneCaption({
  texts,
  index,
  live,
  className,
}: {
  texts: readonly string[];
  index: number;
  /** Announce changes (only when the user is stepping by hand). */
  live: boolean;
  className?: string;
}) {
  return (
    <>
      {/* Always-present polite region: filled only when the visitor steps by hand. */}
      <span className={m.visuallyHidden} aria-live="polite">
        {live ? texts[index] : ""}
      </span>
      <p className={`${m.caption} ${m.captionStack} ${className ?? ""}`}>
        {texts.map((text, idx) =>
          idx === index ? (
            <span key={`current-${idx}`} className={m.captionText}>
              {text}
            </span>
          ) : (
            <span key={idx} className={m.captionGhost} aria-hidden="true">
              {text}
            </span>
          ),
        )}
      </p>
    </>
  );
}
