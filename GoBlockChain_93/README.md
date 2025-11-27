\# GoBlockChain\_08



一个用 Go 语言实现的简化区块链系统，支持交易签名、区块生成、Merkle Tree 和 MPT 账户状态管理。



\## 功能特性

\- ECDSA 数字签名与验证

\- 交易池与区块生成

\- Merkle Tree 验证交易完整性

\- MPT（Merkle Patricia Trie）管理账户状态

\- 命令行交互界面



\## 技术栈

\- Go 语言

\- ECDSA 加密

\- Merkle Tree \& MPT

\- 命令行交互



\## 安装与运行



```bash

\# 克隆项目

git clone https://github.com/yourname/GoBlockChain\_08.git

cd GoBlockChain\_08



\# 运行程序

go run BlockChain.go


使用说明

启动后，按菜单提示操作：

创建账户

发起交易

查看交易池

生成新区块

查看区块链

查看账户列表

查询账户状态

退出系统



\##项目结构



├── BlockChain.go         # 主程序

├── README.md             # 项目说明

├── LICENSE               # MIT 许可证

├── 分支管理记录.md   # Git 分支操作记录

├── .gitignore            # 忽略编译产物等





采用MIT协议，欢迎提交 Issue 和 Pull Request！


