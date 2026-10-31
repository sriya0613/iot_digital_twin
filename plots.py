"""plots.py — evaluation figures for the report (matplotlib, optional)."""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

SURFACE, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e6e5e0"
BLUE, ORANGE = "#2a78d6", "#eb6834"
BAND = {"benign": "#cde2fb", "malware": "#f6d3c4", "unlabeled": "#f0efec"}


def _style(ax):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=9, length=0)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def make_plots(ids, lab, attack, s, cfg, m, global_impact, outdir):
    thr, thr_s = cfg["t_malicious"], cfg["t_suspicious"]
    # ---- 1. threat probability per window ---------------------------------
    fig, (ax, ax2) = plt.subplots(2, 1, figsize=(11, 4.6), sharex=True,
                                  gridspec_kw={"height_ratios": [10, 1], "hspace": 0.08},
                                  facecolor=SURFACE)
    _style(ax)
    ax.vlines(ids[attack], 0, s[attack], color=ORANGE, linewidth=1.2, alpha=0.5)
    ax.scatter(ids[~attack], s[~attack], s=26, color=BLUE, edgecolor=SURFACE, linewidth=1,
               label="Normal window (%d)" % (~attack).sum(), zorder=3)
    ax.scatter(ids[attack], s[attack], s=46, marker="D", color=ORANGE, edgecolor=SURFACE,
               linewidth=1, label="Port-scan window (%d)" % attack.sum(), zorder=4)
    for t, name in ((thr, "malicious"), (thr_s, "suspicious")):
        ax.axhline(t, color=INK2, linewidth=1, linestyle=(0, (4, 3)))
        ax.text(ids.max() + 12, t + 0.015, "%s >= %.2f" % (name, t), va="bottom", ha="right",
                fontsize=9, color=INK2)
    ax.set_ylim(-0.04, 1.08)
    ax.set_ylabel("Threat probability (fused)", color=INK2, fontsize=10)
    ax.set_title("Threat probability per 5-second window — every scan is labelled malicious, no normal window is",
                 loc="left", fontsize=12, color=INK, pad=12)
    ax.legend(frameon=False, fontsize=9, loc="center left", labelcolor=INK2)
    ax.set_xlim(ids.min() - 1.5, ids.max() + 13)

    # manifest-label band
    ax2.set_facecolor(SURFACE)
    for sp_ in ax2.spines.values():
        sp_.set_visible(False)
    ax2.set_yticks([])
    ax2.tick_params(colors=MUTED, labelsize=9, length=0)
    start = 0
    for i in range(1, len(ids) + 1):
        if i == len(ids) or lab[i] != lab[start]:
            ax2.barh(0, ids[i - 1] - ids[start] + 0.8, left=ids[start] - 0.4, height=1,
                     color=BAND.get(lab[start], "#eee"), edgecolor=SURFACE, linewidth=2)
            if i - start >= 4:
                ax2.text((ids[start] + ids[i - 1]) / 2, 0, lab[start], ha="center", va="center",
                         fontsize=8.5, color=INK2)
            start = i
    ax2.text(ids.max() + 1, 0, " manifest label", va="center", ha="left", fontsize=9, color=INK2)
    ax2.set_xlabel("Window id (5 s each)", color=INK2, fontsize=10)
    fig.savefig(os.path.join(outdir, "score_timeline.png"), dpi=160, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)

    # ---- 3. SHAP global feature impact --------------------------------------
    gi = global_impact[:10][::-1]
    fig, ax = plt.subplots(figsize=(7.2, 0.42 * len(gi) + 1.3), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    vals = [g["mean_abs_shap"] for g in gi]
    cols = {"network": BLUE, "syscall": ORANGE, "energy": "#1baf7a"}
    ax.barh(range(len(gi)), vals, height=0.6, color=[cols.get(g.get("monitor", "network"), BLUE) for g in gi])
    mons = [mn for mn in ("network", "syscall", "energy") if any(g.get("monitor") == mn for g in gi)]
    if len(mons) > 1:
        from matplotlib.patches import Patch
        ax.legend(handles=[Patch(color=cols[mn], label=mn) for mn in mons], frameon=False, fontsize=9,
                  loc="lower right", labelcolor=INK2)
    for k, v in enumerate(vals):
        ax.text(v + max(vals) * 0.015, k, "%.2f" % v, va="center", fontsize=9, color=INK2)
    ax.set_yticks(range(len(gi))); ax.set_yticklabels([g["feature"] for g in gi], fontsize=9.5, color=INK2)
    ax.set_xticks([])
    for sp_ in ax.spines.values():
        sp_.set_visible(False)
    ax.tick_params(length=0)
    ax.set_xlim(0, max(vals) * 1.12)
    ax.set_title("SHAP feature impact on the XGBoost model (mean |SHAP|, log-odds)", loc="left",
                 fontsize=12, color=INK, pad=10)
    fig.savefig(os.path.join(outdir, "shap_feature_impact.png"), dpi=160, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)

    if m is None:
        return
    # ---- 2. confusion matrix ----------------------------------------------
    cm = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
    fig, ax = plt.subplots(figsize=(4.6, 3.9), facecolor=SURFACE)
    ax.imshow(cm, cmap=matplotlib.colors.LinearSegmentedColormap.from_list("b", ["#eef5fd", "#256abf"]),
              vmin=0, vmax=cm.max())
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center", fontsize=22,
                    color="white" if cm[i, j] > cm.max() * 0.55 else INK)
    ax.set_xticks([0, 1]); ax.set_xticklabels(["Normal", "Attack"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["Normal", "Attack"], rotation=90, va="center")
    ax.set_xlabel("Detector said", color=INK2); ax.set_ylabel("Actually was", color=INK2)
    ax.tick_params(colors=INK2, length=0)
    for sp_ in ax.spines.values():
        sp_.set_visible(False)
    ax.set_xticks([0.5], minor=True); ax.set_yticks([0.5], minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=3)
    ax.tick_params(which="minor", length=0)
    ax.set_title("Held-out test windows (n=%d)" % cm.sum(), loc="left", fontsize=12, color=INK, pad=10)
    fig.savefig(os.path.join(outdir, "confusion_matrix.png"), dpi=160, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)
