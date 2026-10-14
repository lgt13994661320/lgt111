#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 答案.json 是否完整且符合比赛要求。"""

import json
import sys
from pathlib import Path

OUT = Path(r"D:/GoWork/1")
PKG_ID = "pkg-08e82c8d"
FIXED = "该需求不能直接转换为FOFA搜索语句"


def main():
    questions = json.load(open(OUT / "题目.json", encoding="utf-8"))
    answers_doc = json.load(open(OUT / "答案.json", encoding="utf-8"))
    template = json.load(open(OUT / "答案模板.json", encoding="utf-8"))

    errors = []
    warnings = []

    # 1. 答案文件结构
    if "选手名称" not in answers_doc:
        errors.append("答案.json 缺少 '选手名称' 字段")
    if "参赛包编号" not in answers_doc:
        errors.append("答案.json 缺少 '参赛包编号' 字段")
    if "答案" not in answers_doc:
        errors.append("答案.json 缺少 '答案' 字段")
        return errors, warnings

    answers = answers_doc["答案"]

    # 2. 参赛包编号一致
    if answers_doc.get("参赛包编号") != PKG_ID:
        errors.append(f"参赛包编号错误：{answers_doc.get('参赛包编号')} != {PKG_ID}")
    if template.get("参赛包编号") != PKG_ID:
        errors.append(f"模板参赛包编号错误：{template.get('参赛包编号')}")

    # 3. 题号完整性
    q_qids = [q["题号"] for q in questions]
    a_qids = [a["题号"] for a in answers]
    t_qids = [a["题号"] for a in template["答案"]]

    if sorted(q_qids) != sorted(a_qids):
        missing = set(q_qids) - set(a_qids)
        extra = set(a_qids) - set(q_qids)
        if missing:
            errors.append(f"答案缺少题号：{missing}")
        if extra:
            errors.append(f"答案有多余题号：{extra}")
    if sorted(q_qids) != sorted(t_qids):
        warnings.append("模板题号与题目不完全一致")

    # 4. 题号唯一
    if len(set(a_qids)) != len(a_qids):
        errors.append("答案有重复题号")

    # 5. 每题答案非空
    empty = [a["题号"] for a in answers if not a.get("查询语句")]
    if empty:
        errors.append(f"以下题号答案为空：{empty}")

    # 6. 统计
    total = len(answers)
    fixed = sum(1 for a in answers if a["查询语句"] == FIXED)
    valid = total - fixed

    print(f"[OK] 总题数: {total}")
    print(f"[OK] 有效查询: {valid}")
    print(f"[OK] 固定答案: {fixed}")
    print(f"[OK] 选手: {answers_doc.get('选手名称')}")
    print(f"[OK] 参赛包: {answers_doc.get('参赛包编号')}")

    if errors:
        print("\n[ERRORS]")
        for e in errors:
            print(f"  - {e}")
    if warnings:
        print("\n[WARNINGS]")
        for w in warnings:
            print(f"  - {w}")

    return errors, warnings


if __name__ == "__main__":
    errors, warnings = main()
    sys.exit(1 if errors else 0)
