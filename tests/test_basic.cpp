/**
 * @file test_basic.cpp
 * @brief 基础功能测试程序
 * @author ebpf_file_monitor
 * @version 1.0.0
 * 
 * 该程序用于测试 eBPF 文件监控系统的基本功能，
 * 包括文件打开、读取、写入、关闭等操作，
 * 并验证数据欺骗功能是否正常工作
 */

 #include <iostream>
 #include <fstream>
 #include <string>
 #include <vector>
 #include <chrono>
 #include <thread>
 #include <cstdlib>
 #include <cstring>
 #include <unistd.h>
 #include <sys/stat.h>
 #include <fcntl.h>
 
 // 测试配置
 constexpr const char* TEST_FILE_PATH = "tests/test_docs/test_content.txt";
 constexpr const char* TEST_LOG_PATH = "tests/log/test_basic.log";
 constexpr const char* EXPECTED_ORIGINAL_CONTENT = "这是一段初始测试文件。";
 constexpr const char* EXPECTED_SPOOFED_CONTENT = "这是一段经过修改缓冲区后的内容。";
 
 // 测试结果统计
 struct TestStats {
     int total_tests = 0;
     int passed_tests = 0;
     int failed_tests = 0;
     
     void add_test(bool passed) {
         total_tests++;
         if (passed) {
             passed_tests++;
         } else {
             failed_tests++;
         }
     }
     
     void print_summary() {
         std::cout << "\n=== 测试结果汇总 ===" << std::endl;
         std::cout << "总测试数: " << total_tests << std::endl;
         std::cout << "通过: " << passed_tests << std::endl;
         std::cout << "失败: " << failed_tests << std::endl;
         std::cout << "通过率: " << (total_tests > 0 ? (passed_tests * 100.0 / total_tests) : 0) << "%" << std::endl;
     }
 };
 
 // 全局测试统计
 TestStats g_stats;
 
 /**
  * @brief 打印测试信息
  * @param test_name 测试名称
  * @param passed 是否通过
  * @param message 消息
  */
 void print_test_result(const std::string& test_name, bool passed, const std::string& message = "") {
     std::cout << "[" << (passed ? "PASS" : "FAIL") << "] " << test_name;
     if (!message.empty()) {
         std::cout << " - " << message;
     }
     std::cout << std::endl;
     
     g_stats.add_test(passed);
 }
 
 /**
  * @brief 创建测试文件
  * @return bool 是否成功
  */
 bool create_test_file() {
     std::cout << "\n=== 创建测试文件 ===" << std::endl;
     
     // 创建目录
     system("mkdir -p tests/test_docs");
     system("mkdir -p tests/log");
     
     // 创建测试文件
     std::ofstream file(TEST_FILE_PATH);
     if (!file.is_open()) {
         print_test_result("创建测试文件", false, "无法创建文件");
         return false;
     }
     
     file << EXPECTED_ORIGINAL_CONTENT << std::endl;
     file.close();
     
     // 验证文件内容
     std::ifstream verify_file(TEST_FILE_PATH);
     if (!verify_file.is_open()) {
         print_test_result("验证测试文件", false, "无法打开文件");
         return false;
     }
     
     std::string content;
     std::getline(verify_file, content);
     verify_file.close();
     
     bool success = (content == EXPECTED_ORIGINAL_CONTENT);
     print_test_result("创建测试文件", success, 
                      success ? "文件创建成功" : "文件内容不匹配");
     
     return success;
 }
 
 /**
  * @brief 测试文件打开功能
  * @return bool 是否成功
  */
 bool test_file_open() {
     std::cout << "\n=== 测试文件打开 ===" << std::endl;
     
     // 使用 C 文件接口
     FILE* file = fopen(TEST_FILE_PATH, "r");
     if (!file) {
         print_test_result("文件打开 (C接口)", false, "fopen 失败");
         return false;
     }
     
     fclose(file);
     print_test_result("文件打开 (C接口)", true, "fopen 成功");
     
     // 使用 C++ 文件接口
     std::ifstream cpp_file(TEST_FILE_PATH);
     if (!cpp_file.is_open()) {
         print_test_result("文件打开 (C++接口)", false, "ifstream 失败");
         return false;
     }
     
     cpp_file.close();
     print_test_result("文件打开 (C++接口)", true, "ifstream 成功");
     
     // 使用系统调用
     int fd = open(TEST_FILE_PATH, O_RDONLY);
     if (fd == -1) {
         print_test_result("文件打开 (系统调用)", false, "open 失败");
         return false;
     }
     
     close(fd);
     print_test_result("文件打开 (系统调用)", true, "open 成功");
     
     return true;
 }
 
 /**
  * @brief 测试文件读取功能
  * @return bool 是否成功
  */
 bool test_file_read() {
     std::cout << "\n=== 测试文件读取 ===" << std::endl;
     
     // 测试 C 接口读取
     FILE* file = fopen(TEST_FILE_PATH, "r");
     if (!file) {
         print_test_result("文件读取 (C接口)", false, "无法打开文件");
         return false;
     }
     
     char buffer[1024] = {0};
     size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
     fclose(file);
     
     if (bytes_read == 0) {
         print_test_result("文件读取 (C接口)", false, "读取字节数为0");
         return false;
     }
     
     std::string content(buffer);
     // 移除换行符
     if (!content.empty() && content.back() == '\n') {
         content.pop_back();
     }
     
     std::cout << "读取内容: \"" << content << "\"" << std::endl;
     
     // 检查是否是原始内容或欺骗内容
     bool is_original = (content == EXPECTED_ORIGINAL_CONTENT);
     bool is_spoofed = (content == EXPECTED_SPOOFED_CONTENT);
     
     if (is_original) {
         print_test_result("文件读取 (C接口)", true, "读取到原始内容");
         print_test_result("数据欺骗检测", false, "数据欺骗功能未生效");
     } else if (is_spoofed) {
         print_test_result("文件读取 (C接口)", true, "读取到欺骗内容");
         print_test_result("数据欺骗检测", true, "数据欺骗功能正常");
     } else {
         print_test_result("文件读取 (C接口)", false, "读取到未知内容");
     }
     
     return true;
 }
 
 /**
  * @brief 测试文件写入功能
  * @return bool 是否成功
  */
 bool test_file_write() {
     std::cout << "\n=== 测试文件写入 ===" << std::endl;
     
     const char* test_content = "这是测试写入的内容。";
     const char* temp_file = "tests/test_docs/temp_write_test.txt";
     
     // 测试 C 接口写入
     FILE* file = fopen(temp_file, "w");
     if (!file) {
         print_test_result("文件写入 (C接口)", false, "无法创建文件");
         return false;
     }
     
     size_t bytes_written = fwrite(test_content, 1, strlen(test_content), file);
     fclose(file);
     
     if (bytes_written != strlen(test_content)) {
         print_test_result("文件写入 (C接口)", false, "写入字节数不匹配");
         return false;
     }
     
     // 验证写入内容
     std::ifstream verify_file(temp_file);
     if (!verify_file.is_open()) {
         print_test_result("文件写入验证", false, "无法打开验证文件");
         return false;
     }
     
     std::string written_content;
     std::getline(verify_file, written_content);
     verify_file.close();
     
     bool success = (written_content == test_content);
     print_test_result("文件写入 (C接口)", success, 
                      success ? "写入内容正确" : "写入内容不匹配");
     
     // 清理临时文件
     unlink(temp_file);
     
     return success;
 }
 
 /**
  * @brief 测试多次文件操作
  * @return bool 是否成功
  */
 bool test_multiple_operations() {
     std::cout << "\n=== 测试多次文件操作 ===" << std::endl;
     
     const int num_operations = 5;
     bool all_success = true;
     
     for (int i = 0; i < num_operations; i++) {
         std::cout << "执行第 " << (i + 1) << " 次操作..." << std::endl;
         
         // 打开文件
         FILE* file = fopen(TEST_FILE_PATH, "r");
         if (!file) {
             print_test_result("多次操作 - 打开", false, "第" + std::to_string(i + 1) + "次失败");
             all_success = false;
             continue;
         }
         
         // 读取内容
         char buffer[1024] = {0};
         size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
         fclose(file);
         
         if (bytes_read == 0) {
             print_test_result("多次操作 - 读取", false, "第" + std::to_string(i + 1) + "次失败");
             all_success = false;
             continue;
         }
         
         std::string content(buffer);
         if (!content.empty() && content.back() == '\n') {
             content.pop_back();
         }
         
         std::cout << "  第 " << (i + 1) << " 次读取: \"" << content << "\"" << std::endl;
         
         // 短暂延迟
         std::this_thread::sleep_for(std::chrono::milliseconds(100));
     }
     
     print_test_result("多次文件操作", all_success, 
                      all_success ? "所有操作成功" : "部分操作失败");
     
     return all_success;
 }
 
 /**
  * @brief 测试不同类型文件
  * @return bool 是否成功
  */
 bool test_different_file_types() {
     std::cout << "\n=== 测试不同文件类型 ===" << std::endl;
     
     // 测试 .txt 文件（应该被欺骗）
     bool txt_test = true;
     FILE* txt_file = fopen(TEST_FILE_PATH, "r");
     if (txt_file) {
         fclose(txt_file);
         print_test_result("读取 .txt 文件", true, "操作成功");
     } else {
         print_test_result("读取 .txt 文件", false, "操作失败");
         txt_test = false;
     }
     
     // 创建并测试 .dat 文件（不应该被欺骗）
     const char* dat_file = "tests/test_docs/test.dat";
     std::ofstream create_dat(dat_file);
     if (create_dat.is_open()) {
         create_dat << "这是一个二进制文件测试" << std::endl;
         create_dat.close();
         
         FILE* dat_test = fopen(dat_file, "r");
         if (dat_test) {
             fclose(dat_test);
             print_test_result("读取 .dat 文件", true, "操作成功");
             unlink(dat_file);
         } else {
             print_test_result("读取 .dat 文件", false, "操作失败");
             txt_test = false;
         }
     } else {
         print_test_result("创建 .dat 文件", false, "创建失败");
         txt_test = false;
     }
     
     return txt_test;
 }
 
 /**
  * @brief 测试并发文件操作
  * @return bool 是否成功
  */
 bool test_concurrent_operations() {
     std::cout << "\n=== 测试并发文件操作 ===" << std::endl;
     
     const int num_threads = 3;
     std::vector<std::thread> threads;
     std::vector<bool> results(num_threads, false);
     
     // 创建多个线程同时访问文件
     for (int i = 0; i < num_threads; i++) {
         threads.emplace_back([&results, i]() {
             bool success = true;
             
             for (int j = 0; j < 3; j++) {
                 FILE* file = fopen(TEST_FILE_PATH, "r");
                 if (!file) {
                     success = false;
                     break;
                 }
                 
                 char buffer[1024] = {0};
                 size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
                 fclose(file);
                 
                 if (bytes_read == 0) {
                     success = false;
                     break;
                 }
                 
                 std::this_thread::sleep_for(std::chrono::milliseconds(50));
             }
             
             results[i] = success;
         });
     }
     
     // 等待所有线程完成
     for (auto& t : threads) {
         t.join();
     }
     
     // 检查结果
     bool all_success = true;
     for (int i = 0; i < num_threads; i++) {
         if (!results[i]) {
             all_success = false;
             std::cout << "线程 " << i << " 执行失败" << std::endl;
         }
     }
     
     print_test_result("并发文件操作", all_success, 
                      all_success ? "所有线程成功" : "部分线程失败");
     
     return all_success;
 }
 
 /**
  * @brief 记录测试日志
  * @param message 日志消息
  */
 void log_test_message(const std::string& message) {
     std::ofstream log_file(TEST_LOG_PATH, std::ios::app);
     if (log_file.is_open()) {
         auto now = std::chrono::system_clock::now();
         auto time_t = std::chrono::system_clock::to_time_t(now);
         
         log_file << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") 
                  << "] " << message << std::endl;
         log_file.close();
     }
 }
 
 /**
  * @brief 主函数
  * @param argc 参数个数
  * @param argv 参数数组
  * @return int 退出码
  */
 int main(int argc, char* argv[]) {
     std::cout << "=== eBPF 文件监控系统基础功能测试 ===" << std::endl;
     std::cout << "测试程序 PID: " << getpid() << std::endl;
     std::cout << "测试文件路径: " << TEST_FILE_PATH << std::endl;
     std::cout << "日志文件路径: " << TEST_LOG_PATH << std::endl;
     
     // 记录测试开始
     log_test_message("开始基础功能测试");
     
     // 检查是否有参数
     bool verbose = false;
     if (argc > 1 && strcmp(argv[1], "-v") == 0) {
         verbose = true;
         std::cout << "详细模式已启用" << std::endl;
     }
     
     // 执行测试
     bool all_tests_passed = true;
     
     // 1. 创建测试文件
     if (!create_test_file()) {
         all_tests_passed = false;
     }
     
     // 2. 测试文件打开
     if (!test_file_open()) {
         all_tests_passed = false;
     }
     
     // 3. 测试文件读取
     if (!test_file_read()) {
         all_tests_passed = false;
     }
     
     // 4. 测试文件写入
     if (!test_file_write()) {
         all_tests_passed = false;
     }
     
     // 5. 测试多次操作
     if (!test_multiple_operations()) {
         all_tests_passed = false;
     }
     
     // 6. 测试不同文件类型
     if (!test_different_file_types()) {
         all_tests_passed = false;
     }
     
     // 7. 测试并发操作
     if (!test_concurrent_operations()) {
         all_tests_passed = false;
     }
     
     // 打印测试结果
     g_stats.print_summary();
     
     // 记录测试结束
     log_test_message("测试完成 - " + std::to_string(g_stats.passed_tests) + 
                     "/" + std::to_string(g_stats.total_tests) + " 通过");
     
     std::cout << "\n=== 测试说明 ===" << std::endl;
     std::cout << "1. 如果数据欺骗功能正常，读取 .txt 文件时应该看到修改后的内容" << std::endl;
     std::cout << "2. 请同时观察 eBPF 监控程序的输出日志" << std::endl;
     std::cout << "3. 检查 tests/log/ 目录中的日志文件" << std::endl;
     std::cout << "4. 确保在运行此测试前已启动 eBPF 监控程序" << std::endl;
     
     return all_tests_passed ? 0 : 1;
 }