# chromiumoxide fork — Branching & Commit Policy

> **M5 Smart Browser fork**: `github.com/a-super-cat/chromiumoxide`
> **Upstream**: `github.com/mattsse/chromiumoxide`
> **Baseline**: tag `smart-m5-baseline-v0.9.1` (= upstream v0.9.1, commit `a7e2bb8`)
> **Last updated**: 2026-07-02

---

## 1. 仓库结构

```
github.com/a-super-cat/chromiumoxide (本仓库, fork)
  ├─ main                   = upstream/main 同步镜像(只读,不要 commit)
  ├─ upstream-main          = 跟踪 upstream/main (git branch --set-upstream-to)
  ├─ smart/main             = smart-browser 集成主线(后续 M5 完成后归并到这里)
  ├─ smart/m5-baseline      = M5 baseline = tag smart-m5-baseline-v0.9.1
  └─ smart/stealth-proto    = Stealth.setFingerprintSeed prototype 开发分支

github.com/mattsse/chromiumoxide (upstream)
  └─ main                   = 权威上游,3 月没动,锁 v0.9.1 不追
```

## 2. 分支规则

### 2.1 必须遵守

| 规则 | 详情 |
|---|---|
| ❌ **不在 `main` 上 commit** | `main` = `upstream/main` 同步镜像,任何 commit 会跟 upstream 冲突 |
| ❌ **不在 `upstream-main` 上 commit** | 同上,这个分支专门跟 upstream 同步 |
| ✅ **`smart/*` 分支才是工作分支** | 所有 M5 改动在 `smart/m5-baseline` / `smart/stealth-proto` 上做 |
| ✅ **`upstream/pr/*` 留作后续 PR 流程** | 见 §3, 这次 M5 不开 PR (留给 M5.9 之后) |

### 2.2 推荐工作流

```bash
# 日常开发
git checkout smart/stealth-proto
# ... commit changes
git push origin smart/stealth-proto

# 同步 upstream 新 commit (M5 期间不推荐,M5 后月度 sync)
git fetch upstream
git checkout upstream-main
git reset --hard upstream/main
git checkout smart/main
git merge upstream-main    # 或 git rebase upstream-main (保持线性)
```

## 3. Commit 标记规范

每个 commit message 头部必须带一个标记,标明它对 upstream 的可推送性:

| 标记 | 含义 | 操作 |
|---|---|---|
| `upstreamable:` | 此 commit 可直接 PR 到 mattsse/chromiumoxide | cherry-pick 到 `upstream/pr/<topic>` 分支发 PR |
| `smart-only:` | 此 commit 只在 fork 内部使用 | 绝不能 PR 到 upstream |
| `generated:` | 此 commit 涉及 generated code 重新生成 | 单独 commit, 不和 stealth 改动混 |

### 3.1 示例

```bash
# good: stealth 改动,smart-only
git commit -m "smart-only: chromiumoxide/src/stealth/ SetFingerprintSeedParams struct"

# good: 修 typo,upstreamable
git commit -m "upstreamable: docs(smart_wait): fix typo in recovery example"

# good: 重新生成 cdp
git commit -m "generated: chromiumoxide_cdp v0.9.1 → v0.9.2 regen from upstream PDL"

# bad: 混合
git commit -m "fix stealth and update docs"  # 不要这样,应该拆成两个 commit
```

## 4. upstream PR 流程

### 4.1 第一次 PR 必须是 `upstreamable:`

按 M5 验收标准 §3.1 AC-17,第一次 PR 提交**非 stealth** 的小修 / 测试 / 文档,目的是:
- 验证 maintainer 响应速度
- 验证 CI 是否跑通
- 熟悉 PR review 风格

候选 PR 主题(从 upstream 53 open issues + commit 历史找):
- 文档 typo 修正
- 缺失测试补充
- clippy warning 修正
- dependency metadata 清理

### 4.2 提交流程

```bash
# 1. 基于 upstream-main 开 PR 分支
git checkout upstream-main
git checkout -b upstream/pr/<short-topic>

# 2. cherry-pick upstreamable commits (从 smart/* 分支)
git cherry-pick <commit-sha-1>
git cherry-pick <commit-sha-2>

# 3. 验证 PR 干净
cargo check
cargo test --lib

# 4. push 到 fork
git push -u origin upstream/pr/<short-topic>

# 5. 在 GitHub 网页开 PR: a-super-cat/upstream/pr/<short-topic> -> mattsse/chromiumoxide main
```

### 4.3 stealth 改动绝对不发 upstream PR

- `chromiumoxide/src/stealth/*` 整个目录是 smart-only
- 任何包含 `Stealth.setFingerprintSeed` 字样的 commit 都是 smart-only
- stealth work 永远留在 `smart/stealth-proto` 分支

## 5. Rebase 策略

### 5.1 M5 期间 (现在到 M5 完成)

**禁止 rebase upstream-main**, 锁 baseline 在 `smart-m5-baseline-v0.9.1`。

只允许:
- cherry-pick 安全修复 (e.g. CVE patch, build fix)
- 接受 `smart/stealth-proto` 的 fast-forward (M5 内部迭代)

### 5.2 M5 完成后

建立月度 sync 节奏:
1. `git fetch upstream`
2. 在新分支 `smart/rebase/YYYY-MM` 上 rebase 到最新 `upstream-main`
3. `cargo check --workspace` + `cargo test --workspace` 验证
4. 通过后 merge 回 `smart/main`
5. 更新 baseline tag: `smart-m5-baseline-v0.9.2` / `.3` / ...

## 6. 关键不变量 (Critical Invariants)

| 不变量 | 验证方法 |
|---|---|
| `smart/m5-baseline` HEAD == upstream `v0.9.1` | `git rev-parse smart/m5-baseline` 应等于 `a7e2bb8` |
| `main` HEAD == `upstream/main` HEAD | `git log --oneline main..upstream/main` 应为空 |
| `chromiumoxide_cdp` generated code 不被手改 | `git log --oneline smart/stealth-proto -- chromiumoxide_cdp/` 应仅含 `generated:` 标记 commits |
| `chromiumoxide/src/stealth/` 不污染 upstream | 任何 PR 到 `mattsse/chromiumoxide` 不应触及此目录 |

## 7. 应急 (Emergency)

如果 `smart/stealth-proto` 被搞坏, 回退到 baseline:
```bash
git checkout smart/m5-baseline
git branch -D smart/stealth-proto    # 删掉坏分支
git checkout -b smart/stealth-proto  # 从 baseline 重建
```

如果 `main` 跟 upstream 失同步:
```bash
git checkout main
git reset --hard upstream/main
git push --force-with-lease origin main
```

---

**Reference**: 详细策略见 `docs/superpowers/plans/2026-07-02-cef-stealth-fork-M5-checklist.md` §3 (acceptance) / §6 (maintain) / §7 (extend).
