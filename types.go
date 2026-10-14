package main

// Question 表示题目 JSON 中的一项。
type Question struct {
	QuestionID      string `json:"题号"`
	NaturalLanguage string `json:"自然语言输入"`
}

// Answer 表示答案 JSON 中的一项。
type Answer struct {
	QuestionID string `json:"题号"`
	Query      string `json:"查询语句"`
}

// AnswerDoc 是最终提交的答案文件结构。
type AnswerDoc struct {
	PlayerName string   `json:"选手名称"`
	PackageID  string   `json:"参赛包编号"`
	Answers    []Answer `json:"答案"`
}

// 不存在 FOFA 直接语法的查询（固定答案）。
const fixedAnswer = "该需求不能直接转换为FOFA搜索语句"
