"""把"运营能看什么"落成 Directus 的策略与权限（只写策略与权限，不建账号）。

为什么不能用 REST 建策略：实测 POST /policies 对超级管理员也返回 403 FORBIDDEN
（docs/03 K-10），而角色↔策略的关联在 directus_access 表里、policies 表没有 roles 列（K-11）。
所以这一步只能直接写库；写完必须重启容器——Directus 把权限缓存在进程里（P8 实测）。

三条来自实测的硬约束，配错了会"看着没问题其实读不到"：
  · 权限行的 fields 必须显式给全：留空的读权限只回主键，留空的写权限直接 403（K-9）。
  · 屏蔽用白名单不用黑名单：以后新增一列敏感字段，默认是不可见（docs/03 D-2）。
  · 没有单列主键的表，平台连超管都读不到（K-12）——那些计数交给运维 API。

运营账号本身不在这里建：口令要由 Directus 自己算 bcrypt，
而 POST /users 是实测可用的（P7/P9），所以账号由 bootstrap.sh 走 API 创建。
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import uuid

DB_PATH = os.environ.get("QINGSU_DB", "/opt/qingsu/data/qingsu.db")
POLICY_NAME = "轻塑运营策略"
ROLE_NAME = "轻塑运营"

# docs/02 §3 的敏感列黑名单：白名单 = 表里的真实列 减掉这些
SENSITIVE = {
    ("users", "password_hash"), ("users", "pw_salt"), ("users", "token"),
    ("users", "token_hash"), ("users", "share_secret"),
    ("sessions", "token_hash"),
    ("email_codes", "code_hash"), ("email_codes", "email_hash"),
    ("profiles", "loc_lat"), ("profiles", "loc_lng"),
    ("ai_memory", "mem_value"), ("private_ai_answers", "answer"), ("kb_entries", "answer"),
    ("body_cycles", "photo_url"), ("media_uploads", "name"), ("posts", "images"),
}
# 能改的表与动作；写权限必须显式列出可写字段（K-9），所以这里一并给出
WRITES = {}  # Business writes go through the audited operations API.
READ_FIELDS = {'ai_memory': ('user_id', 'mem_key', 'updated_at'),
 'body_cycles': ('id',
                 'user_id',
                 'cycle_num',
                 'cycle_name',
                 'weight_jin',
                 'waist_cm',
                 'tone_score',
                 'ai_report',
                 'created_at'),
 'checklist_state': ('user_id', 'log_date', 'state_json', 'updated_at'),
 'cheers': ('id', 'user_id', 'kind', 'sender_hash', 'cheer_date', 'created_at'),
 'comment_likes': ('comment_id', 'user_id', 'created_at'),
 'comments': ('id',
              'post_id',
              'user_id',
              'reply_to',
              'body',
              'region',
              'request_id',
              'status',
              'created_at',
              'images',
              'like_count'),
 'community_profile': ('user_id',
                       'bio',
                       'region',
                       'region_seen_at',
                       'discoverable',
                       'updated_at',
                       'bubble_theme'),
 'content_reports': ('id',
                     'target_kind',
                     'target_id',
                     'reporter',
                     'reason',
                     'status',
                     'handled_at',
                     'handled_note',
                     'created_at'),
 'conversations': ('conv_key', 'a_id', 'b_id', 'last_body', 'last_at', 'last_from', 'created_at'),
 'daily_metrics': ('user_id', 'log_date', 'metrics_json', 'origin'),
 'daily_modes': ('user_id', 'log_date', 'mode'),
 'daily_reviews': ('user_id', 'log_date', 'complete'),
 'email_codes': ('id', 'purpose', 'expires_at', 'attempts', 'created_at'),
 'feedback': ('id',
              'user_id',
              'kind',
              'body',
              'page',
              'app_build',
              'contact',
              'status',
              'reply',
              'created_at',
              'replied_at'),
 'follows': ('follower_id', 'followee_id', 'created_at'),
 'food_logs': ('id',
               'user_id',
               'log_date',
               'slot',
               'food_name',
               'cal',
               'protein_g',
               'carbs_g',
               'fat_g',
               'time_str',
               'created_at',
               'source',
               'estimate_reason'),
 'kb_entries': ('qkey', 'sources', 'fetched_at', 'hits'),
 'media_uploads': ('user_id', 'created_at', 'kind', 'mime', 'duration', 'metadata'),
 'mentions': ('id', 'post_id', 'comment_id', 'user_id', 'actor_id', 'created_at'),
 'messages': ('id',
              'conv_key',
              'from_id',
              'to_id',
              'body',
              'request_id',
              'created_at',
              'read_at',
              'recalled_at',
              'kind',
              'media_name',
              'media_mime',
              'media_size',
              'media_w',
              'media_h',
              'media_dur',
              'media_meta',
              'asr_text',
              'quote_id',
              'quote_name',
              'quote_kind',
              'quote_snippet'),
 'notifications': ('id',
                   'user_id',
                   'kind',
                   'actor_id',
                   'post_id',
                   'comment_id',
                   'body_text',
                   'dedup',
                   'created_at',
                   'read_at'),
 'post_favorites': ('post_id', 'user_id', 'created_at'),
 'post_likes': ('post_id', 'user_id', 'created_at'),
 'posts': ('id',
           'user_id',
           'body',
           'like_count',
           'comment_count',
           'region',
           'request_id',
           'status',
           'created_at',
           'edited_at',
           'title'),
 'private_ai_answers': ('user_id', 'question', 'updated_at'),
 'profiles': ('user_id',
              'gender',
              'age',
              'height',
              'weight_jin',
              'target_weight_jin',
              'goal_type',
              'dining_mode',
              'scene',
              'updated_at',
              'day_mode',
              'cycle_started_at',
              'email',
              'email_verified_at',
              'avatar_url',
              'city',
              'city_source',
              'avoid_tags',
              'loc_updated_at'),
 'push_subscriptions': ('user_id', 'last_notice', 'last_message', 'failures', 'updated_at'),
 'record_changes': ('id', 'user_id', 'kind', 'record_id', 'previous_json', 'operation', 'created_at'),
 'request_receipts': ('user_id', 'request_key', 'kind', 'created_at'),
 'sessions': ('user_id', 'expires_at'),
 'share_settings': ('user_id', 'enabled', 'expires_at', 'scope'),
 'shared_goal_members': ('goal_id', 'user_id'),
 'shared_goals': ('id', 'owner_id', 'title', 'kind', 'target', 'start_date', 'end_date'),
 'takeout_events': ('id', 'user_id', 'event_type', 'cal_avoided', 'dish_name', 'log_date', 'created_at'),
 'user_blocks': ('blocker', 'blocked', 'created_at'),
 'user_cities': ('user_id', 'city', 'first_seen', 'last_seen', 'hits'),
 'users': ('id', 'username', 'nickname', 'created_at', 'banned_at', 'ban_reason', 'public_id'),
 'water_logs': ('user_id', 'log_date', 'cups_count', 'updated_at'),
 'weight_logs': ('id', 'user_id', 'log_date', 'weight_jin', 'waist_cm', 'created_at'),
 'workout_logs': ('id', 'user_id', 'log_date', 'duration_minutes', 'cal_burned', 'plan_name', 'created_at')}

# 运营用不上的表：不给入口，免得在 34 张表里翻
HIDE = {"request_receipts", "checklist_state", "user_cities", "daily_reviews"}


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, timeout=5)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=5000")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def table_names(c):
    return [r[0] for r in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
        "AND name NOT LIKE 'directus_%' AND name <> 'admin_audit' ORDER BY name")]


def single_pk(c, table):
    """Directus 只服务单列主键的表；复合主键在 schema 同步时被直接忽略（K-12）。"""
    pks = [r[1] for r in c.execute("PRAGMA table_info(%s)" % table) if r[5]]
    return pks[0] if len(pks) == 1 else None


def cols_of(c, table):
    return [r[1] for r in c.execute("PRAGMA table_info(%s)" % table)]


def ensure_collection_meta(c, tables):
    """把已存在的业务表注册成"受管理集合"。

    为什么不注册就会空：Directus 的"内容"导航读的是 directus_collections 元数据，
    不是数据库里的表。表存在、接口能读，但元数据 0 行时 Studio 显示"没有任何模型"（实测）。
    POST /collections 会以"已存在"拒绝，所以这里直接补 meta 行（只加展示元数据，不动表结构）。
    """
    have = {r[0] for r in c.execute("SELECT collection FROM directus_collections")}
    added = []
    for t in tables:
        if t in have:
            continue
        c.execute("INSERT INTO directus_collections"
                  "(collection,icon,note,hidden,singleton,archive_app_filter,accountability)"
                  " VALUES (?,?,?,0,0,1,'all')", (t, "box", ""))
        added.append(t)
    return added


def ensure_report_status(c):
    """举报表原本没有状态列：投进去就沉底，M-31"处理完不再出现在待处理里"在结构上无处落脚。
    这里补三列（都带默认值，主应用不读它们，所以行为不变）。

    更干净的归属是让主应用的 _ensure_columns 也认这几列，那要另开一次发版；
    本轮先在后台侧补，并把这条差异记进 docs/02 与交付说明。
    """
    have = set(cols_of(c, "content_reports"))
    added = []
    for name, ddl in (("status", "TEXT NOT NULL DEFAULT 'new'"),
                      ("handled_at", "TEXT"),
                      ("handled_note", "TEXT NOT NULL DEFAULT ''")):
        if name not in have:
            c.execute("ALTER TABLE content_reports ADD COLUMN %s %s" % (name, ddl))
            added.append(name)
    if added:
        c.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON content_reports(status, id DESC)")
    return added


def main() -> int:
    c = conn()
    if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='directus_policies'").fetchone():
        print("Directus 还没 bootstrap（没有 directus_policies 表），先起容器再播种")
        return 2
    added = ensure_report_status(c)
    c.commit()

    servable, ignored = [], []
    for t in table_names(c):
        (servable if single_pk(c, t) else ignored).append(t)

    role = c.execute("SELECT id FROM directus_roles WHERE name=?", (ROLE_NAME,)).fetchone()
    role_id = role[0] if role else str(uuid.uuid4())
    if not role:
        # Directus 11 的 roles 表只有 (id,name,icon,description,parent)：
        # admin_access/app_access 早搬到 policies 上了，写进来就是 OperationalError（本轮踩过）。
        c.execute("INSERT INTO directus_roles (id,name,icon) VALUES (?,?,?)", (role_id, ROLE_NAME, "lock"))

    policy = c.execute("SELECT id FROM directus_policies WHERE name=?", (POLICY_NAME,)).fetchone()
    policy_id = policy[0] if policy else str(uuid.uuid4())
    if not policy:
        c.execute("INSERT INTO directus_policies (id,name,icon,description,enforce_tfa,admin_access,app_access)"
                  " VALUES (?,?,?,?,0,0,1)",
                  (policy_id, POLICY_NAME, "lock", "后台日常运营：只看明细，高危动作走运维页"))
        c.execute("INSERT INTO directus_access (id, role, policy) VALUES (?,?,?)",
                  (str(uuid.uuid4()), role_id, policy_id))

    # 权限整体重建：不清就可能出现"上一版的白名单还挂着已经删掉的列"
    c.execute("DELETE FROM directus_permissions WHERE policy=?", (policy_id,))
    granted, hidden, actions = [], [], []
    for t in servable:
        if t in HIDE:
            hidden.append(t)
            continue
        whitelist = [col for col in READ_FIELDS.get(t, ()) if col in cols_of(c, t) and (t, col) not in SENSITIVE]
        if t == "messages":
            whitelist = [field for field in whitelist if field not in {"body", "asr_text", "media_name", "media_meta", "quote_snippet", "quote_name"}]
        if t == "conversations":
            whitelist = [field for field in whitelist if field != "last_body"]
        if not whitelist:
            continue
        # fields 必须是**逗号分隔字符串**，不是 JSON 数组：
        # 写成数组时 Directus 会翻译成"一个字段都不许读"，接口只回主键——实测过两次才定位到。
        c.execute("INSERT INTO directus_permissions (collection,action,policy,permissions,fields)"
                  " VALUES (?,'read',?,?,?)", (t, policy_id, json.dumps({"_and": []}), ",".join(whitelist)))
        actions.append("%s.read(%d列)" % (t, len(whitelist)))
        for action, writable in (WRITES.get(t) or {}).items():
            fields = writable if writable else None
            if fields:
                missing = set(fields) - set(whitelist)
                if missing:
                    raise SystemExit("%s 想放开 %s，但这些列不在白名单里：%s" % (t, action, sorted(missing)))
            c.execute("INSERT INTO directus_permissions (collection,action,policy,permissions,fields)"
                      " VALUES (?,?,?,?,?)",
                      (t, action, policy_id, json.dumps({"_and": []}),
                       ",".join(fields) if fields else None))
            actions.append("%s.%s" % (t, action))
        granted.append(t)

    meta_added = ensure_collection_meta(c, granted)
    c.commit()
    c.close()
    print(json.dumps({"补的列": added, "注册的集合元数据": meta_added,
                      "可服务表": len(servable), "复合主键被忽略": ignored,
                      "授权": actions, "隐藏": hidden, "角色": role_id, "策略": policy_id},
                     ensure_ascii=False, indent=1))
    print("NEXT: docker restart qingsu-console（权限有进程内缓存，不重启读不到）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
