// Package main 提供 FOFA 自然语言到 FOFA Query 的转换器命令行工具。
//
// 用法：
//   go run .                           使用当前目录下的 题目.json 生成 答案.json
//   go run . -i 题目.json -o 答案.json 指定输入输出
//   go run . -q "请查询 IP 地址为 1.1.1.1 的资产。"  单条查询转换
//
// 输出 JSON 格式遵循比赛要求的 答案.json 结构。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	var (
		inputPath  = flag.String("i", "题目.json", "题目 JSON 文件路径")
		outputPath = flag.String("o", "答案.json", "输出答案 JSON 文件路径")
		query      = flag.String("q", "", "单条自然语言查询语句（调试模式）")
		playerName = flag.String("p", "GoEngineer-参赛者", "选手名称")
		pkgID      = flag.String("pkg", "pkg-08e82c8d", "参赛包编号")
	)
	flag.Parse()

	if *query != "" {
		// 单条调试模式
		ans := Convert(*query)
		fmt.Println(ans)
		return
	}

	// 加载题目
	questions, err := loadQuestions(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] 加载题目失败：%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[INFO] 已加载 %d 道题目\n", len(questions))

	// 转换
	answers := make([]Answer, 0, len(questions))
	for _, q := range questions {
		answers = append(answers, Answer{
			QuestionID: q.QuestionID,
			Query:      Convert(q.NaturalLanguage),
		})
	}

	// 输出
	doc := AnswerDoc{
		PlayerName:   *playerName,
		PackageID:    *pkgID,
		Answers:      answers,
	}
	if err := writeJSON(*outputPath, doc); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] 写入失败：%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[OK] 已生成 %d 道答案 -> %s\n", len(answers), *outputPath)
}

// loadQuestions 读取题目 JSON 文件。
func loadQuestions(path string) ([]Question, error) {
	abs, _ := filepath.Abs(path)
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	var qs []Question
	if err := json.Unmarshal(data, &qs); err != nil {
		return nil, err
	}
	return qs, nil
}

// writeJSON 将答案文档写入 JSON 文件（UTF-8，无 BOM，缩进）。
func writeJSON(path string, doc AnswerDoc) error {
	abs, _ := filepath.Abs(path)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(abs, data, 0o644)
}
