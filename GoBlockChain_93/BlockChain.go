package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

// ================= 数据结构定义 =================
type Block struct {
	Index        int           `json:"index"`
	Timestamp    string        `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	PrevHash     string        `json:"prevHash"`
	Hash         string        `json:"hash"`
	MerkleRoot   string        `json:"merkleRoot"`
}

type Transaction struct {
	ID        string `json:"id"`        // 交易ID
	From      string `json:"from"`      // 发送方地址（公钥哈希）
	To        string `json:"to"`        // 接收方地址
	Amount    int    `json:"amount"`    // 金额
	Signature string `json:"signature"` // 交易签名
	PublicKey string `json:"publicKey"` // 发送方公钥（用于验证）
}

type Account struct {
	Address    string            `json:"address"`   // 账户地址（公钥哈希）
	Balance    int               `json:"balance"`   // 账户余额
	PrivateKey *ecdsa.PrivateKey `json:"-"`         // 私钥（不存储）
	PublicKey  *ecdsa.PublicKey  `json:"publicKey"` // 公钥
}

type MPTNode struct {
	Key      string            `json:"key"`
	Value    string            `json:"value"`
	Children map[byte]*MPTNode `json:"children"`
}

type Blockchain struct {
	Blocks        []Block
	Accounts      map[string]*Account
	TxPool        []Transaction
	AccountTrie   *MPTNode
	PendingBlocks []Block
}

// ================= 加密功能 =================
// 生成ECDSA密钥对
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// 公钥转字符串
func PublicKeyToString(pub *ecdsa.PublicKey) string {
	return fmt.Sprintf("%x%x", pub.X.Bytes(), pub.Y.Bytes())
}

// 字符串转公钥
func StringToPublicKey(pubStr string) (*ecdsa.PublicKey, error) {
	if len(pubStr) != 128 {
		return nil, fmt.Errorf("invalid public key length")
	}

	xBytes, err := hex.DecodeString(pubStr[:64])
	if err != nil {
		return nil, err
	}

	yBytes, err := hex.DecodeString(pubStr[64:])
	if err != nil {
		return nil, err
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// 从公钥生成地址（公钥的SHA-256哈希）
func PublicKeyToAddress(pub *ecdsa.PublicKey) string {
	pubBytes := append(pub.X.Bytes(), pub.Y.Bytes()...)
	hash := sha256.Sum256(pubBytes)
	return hex.EncodeToString(hash[:])[:40] // 取前40个字符作为地址
}

// 签名交易
func SignTransaction(tx *Transaction, privateKey *ecdsa.PrivateKey) error {
	// 创建交易数据的哈希
	txData := fmt.Sprintf("%s%s%s%d", tx.ID, tx.From, tx.To, tx.Amount)
	hash := sha256.Sum256([]byte(txData))

	// 使用私钥签名
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return err
	}

	// 将签名编码为十六进制字符串
	signature := append(r.Bytes(), s.Bytes()...)
	tx.Signature = hex.EncodeToString(signature)
	return nil
}

// 验证交易签名
func VerifyTransaction(tx Transaction) bool {
	// 解析公钥
	pubKey, err := StringToPublicKey(tx.PublicKey)
	if err != nil {
		fmt.Printf("解析公钥失败: %v\n", err)
		return false
	}

	// 创建交易数据的哈希
	txData := fmt.Sprintf("%s%s%s%d", tx.ID, tx.From, tx.To, tx.Amount)
	hash := sha256.Sum256([]byte(txData))

	// 解码签名
	signature, err := hex.DecodeString(tx.Signature)
	if err != nil {
		fmt.Printf("解码签名失败: %v\n", err)
		return false
	}

	// 分离R和S值
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])

	// 验证签名
	return ecdsa.Verify(pubKey, hash[:], r, s)
}

// ================= 系统初始化 =================
func NewBlockchain() *Blockchain {
	bc := &Blockchain{
		Accounts: make(map[string]*Account),
		AccountTrie: &MPTNode{
			Children: make(map[byte]*MPTNode),
		},
	}
	bc.createGenesisBlock()
	return bc
}

func (bc *Blockchain) createGenesisBlock() {
	// 创建创世账户
	privateKey, publicKey, _ := GenerateKeyPair()
	genesisAddress := PublicKeyToAddress(publicKey)

	genesisAccount := &Account{
		Address:    genesisAddress,
		Balance:    1000000,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	bc.Accounts[genesisAccount.Address] = genesisAccount
	bc.AccountTrie.Insert(genesisAccount.Address, strconv.Itoa(genesisAccount.Balance))

	// 创建创世区块
	genesisBlock := Block{
		Index:        0,
		Timestamp:    time.Now().Format(time.RFC3339),
		Transactions: []Transaction{},
		PrevHash:     "",
	}
	genesisBlock.Hash = CalculateHash(genesisBlock)
	bc.Blocks = append(bc.Blocks, genesisBlock)
}

// ================= Merkle Tree 实现 =================
func ComputeMerkleRoot(txs []Transaction) string {
	if len(txs) == 0 {
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}
	txHashes := make([]string, len(txs))
	for i, tx := range txs {
		data, _ := json.Marshal(tx)
		hash := sha256.Sum256(data)
		txHashes[i] = hex.EncodeToString(hash[:])
	}

	for len(txHashes) > 1 {
		var newLevel []string
		for i := 0; i < len(txHashes); i += 2 {
			left := txHashes[i]
			right := left
			if i+1 < len(txHashes) {
				right = txHashes[i+1]
			}
			combined := left + right
			hash := sha256.Sum256([]byte(combined))
			newLevel = append(newLevel, hex.EncodeToString(hash[:]))
		}
		txHashes = newLevel
	}
	return txHashes[0]
}

// ================= MPT 实现 =================
func (n *MPTNode) Insert(key, value string) {
	current := n
	for i := 0; i < len(key); i++ {
		char := key[i]
		if current.Children == nil {
			current.Children = make(map[byte]*MPTNode)
		}
		if current.Children[char] == nil {
			current.Children[char] = &MPTNode{}
		}
		current = current.Children[char]
	}
	current.Key = key
	current.Value = value
}

func (n *MPTNode) Get(key string) (string, bool) {
	current := n
	for i := 0; i < len(key); i++ {
		char := key[i]
		if current.Children == nil || current.Children[char] == nil {
			return "", false
		}
		current = current.Children[char]
	}
	if current.Value == "" {
		return "", false
	}
	return current.Value, true
}

// ================= 区块链操作 =================
func CalculateHash(block Block) string {
	record := fmt.Sprintf("%d%s%s%s", block.Index, block.Timestamp, block.MerkleRoot, block.PrevHash)
	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

func (bc *Blockchain) GenerateBlock() Block {
	if len(bc.TxPool) == 0 {
		fmt.Println("交易池为空，无法生成新区块")
		return Block{}
	}

	// 验证交易池中的所有交易
	var validTxs []Transaction
	for _, tx := range bc.TxPool {
		if VerifyTransaction(tx) {
			validTxs = append(validTxs, tx)
		} else {
			fmt.Printf("⚠ 无效交易已移除: %s\n", tx.ID)
		}
	}

	// 更新交易池
	bc.TxPool = validTxs

	if len(validTxs) == 0 {
		fmt.Println("没有有效交易，无法生成新区块")
		return Block{}
	}

	lastBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := Block{
		Index:        lastBlock.Index + 1,
		Timestamp:    time.Now().Format(time.RFC3339),
		Transactions: validTxs,
		PrevHash:     lastBlock.Hash,
	}
	newBlock.MerkleRoot = ComputeMerkleRoot(newBlock.Transactions)
	newBlock.Hash = CalculateHash(newBlock)
	return newBlock
}

func (bc *Blockchain) AddBlock(block Block) {
	// 验证区块
	if block.PrevHash != bc.Blocks[len(bc.Blocks)-1].Hash {
		fmt.Println("区块验证失败: 前一个区块哈希不匹配")
		return
	}

	// 执行交易
	for _, tx := range block.Transactions {
		// 验证发送方余额
		sender := bc.Accounts[tx.From]
		if sender == nil {
			fmt.Printf("发送方账户不存在: %s\n", tx.From)
			continue
		}
		if sender.Balance < tx.Amount {
			fmt.Printf("余额不足: %s (余额: %d, 需要: %d)\n", tx.From, sender.Balance, tx.Amount)
			continue
		}

		// 更新发送方余额
		sender.Balance -= tx.Amount
		bc.AccountTrie.Insert(sender.Address, strconv.Itoa(sender.Balance))

		// 更新接收方余额
		receiver := bc.Accounts[tx.To]
		if receiver == nil {
			// 创建新账户（只有地址，没有私钥）
			receiver = &Account{
				Address: tx.To,
				Balance: 0,
			}
			bc.Accounts[tx.To] = receiver
			bc.AccountTrie.Insert(tx.To, "0")
		}
		receiver.Balance += tx.Amount
		bc.AccountTrie.Insert(receiver.Address, strconv.Itoa(receiver.Balance))
	}

	bc.Blocks = append(bc.Blocks, block)
	bc.TxPool = []Transaction{} // 清空交易池
	fmt.Printf(" 区块 #%d 已添加到区块链\n", block.Index)
}

// ================= 账户管理 =================
func (bc *Blockchain) CreateAccount(label string, initialBalance int) *Account {
	// 生成密钥对
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		fmt.Printf("创建账户失败: %v\n", err)
		return nil
	}

	// 生成地址
	address := PublicKeyToAddress(publicKey)

	// 创建账户
	newAccount := &Account{
		Address:    address,
		Balance:    initialBalance,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	bc.Accounts[address] = newAccount
	bc.AccountTrie.Insert(address, strconv.Itoa(initialBalance))

	fmt.Printf(" 账户创建成功\n")
	fmt.Printf("  标签: %s\n", label)
	fmt.Printf("  地址: %s\n", address)
	fmt.Printf("  余额: %d\n", initialBalance)

	return newAccount
}

func (bc *Blockchain) AddTransaction(fromAcc *Account, to string, amount int) {
	// 验证接收方
	if _, exists := bc.Accounts[to]; !exists {
		fmt.Printf("接收方账户不存在: %s\n", to)
		return
	}

	// 验证金额
	if amount <= 0 {
		fmt.Println("交易金额必须大于0")
		return
	}

	// 验证发送方余额
	if fromAcc.Balance < amount {
		fmt.Printf("余额不足: %s (余额: %d, 需要: %d)\n", fromAcc.Address, fromAcc.Balance, amount)
		return
	}

	// 创建交易
	tx := Transaction{
		ID:        fmt.Sprintf("tx%d", time.Now().UnixNano()),
		From:      fromAcc.Address,
		To:        to,
		Amount:    amount,
		PublicKey: PublicKeyToString(fromAcc.PublicKey),
	}

	// 签名交易
	if err := SignTransaction(&tx, fromAcc.PrivateKey); err != nil {
		fmt.Printf("交易签名失败: %v\n", err)
		return
	}

	bc.TxPool = append(bc.TxPool, tx)
	fmt.Printf(" 交易已添加到交易池: %s -> %s (%d)\n", fromAcc.Address, to, amount)
}

// ================= 系统状态查询 =================
func (bc *Blockchain) PrintBlockchain() {
	fmt.Println("\n===== 区块链状态 =====")
	fmt.Printf("区块数量: %d\n", len(bc.Blocks))
	fmt.Printf("账户数量: %d\n", len(bc.Accounts))
	fmt.Printf("交易池中的交易数: %d\n", len(bc.TxPool))
}

func (bc *Blockchain) PrintAccounts() {
	fmt.Println("\n===== 账户列表 =====")
	for addr, acc := range bc.Accounts {
		fmt.Printf("地址: %s, 余额: %d\n", addr, acc.Balance)
	}
}

func (bc *Blockchain) PrintTxPool() {
	fmt.Println("\n===== 交易池 =====")
	if len(bc.TxPool) == 0 {
		fmt.Println("交易池为空")
		return
	}
	for i, tx := range bc.TxPool {
		valid := "✓"
		if !VerifyTransaction(tx) {
			valid = "✗"
		}
		fmt.Printf("%d. [%s] %s -> %s: %d (ID: %s)\n", i+1, valid, tx.From, tx.To, tx.Amount, tx.ID)
	}
}

func (bc *Blockchain) PrintBlocks() {
	fmt.Println("\n===== 区块列表 =====")
	for _, block := range bc.Blocks {
		fmt.Printf("区块 #%d [%s]\n", block.Index, block.Timestamp)
		fmt.Printf("  哈希: %s\n", block.Hash)
		fmt.Printf("  前一个哈希: %s\n", block.PrevHash)
		fmt.Printf("  Merkle根: %s\n", block.MerkleRoot)
		fmt.Printf("  交易数: %d\n", len(block.Transactions))
	}
}

func (bc *Blockchain) PrintAccountState(address string) {
	acc, exists := bc.Accounts[address]
	if !exists {
		fmt.Printf("账户不存在: %s\n", address)
		return
	}

	value, _ := bc.AccountTrie.Get(address)
	fmt.Printf("\n账户地址: %s\n", address)
	fmt.Printf("  余额: %d\n", acc.Balance)
	fmt.Printf("  MPT值: %s\n", value)
}

// ================= 命令行界面 =================
func printMenu() {
	fmt.Println("\n===== 区块链系统菜单 =====")
	fmt.Println("1. 创建账户")
	fmt.Println("2. 发起交易")
	fmt.Println("3. 查看交易池")
	fmt.Println("4. 生成新区块")
	fmt.Println("5. 查看区块链")
	fmt.Println("6. 查看账户列表")
	fmt.Println("7. 查询账户状态")
	fmt.Println("8. 退出系统")
	fmt.Print("请选择操作: ")
}

func main() {
	bc := NewBlockchain()
	reader := bufio.NewReader(os.Stdin)

	// 账户映射（标签 -> 账户）
	accounts := make(map[string]*Account)

	// 创建一些初始账户
	alice := bc.CreateAccount("Alice", 1000)
	bob := bc.CreateAccount("Bob", 500)
	charlie := bc.CreateAccount("Charlie", 300)

	if alice != nil {
		accounts["Alice"] = alice
	}
	if bob != nil {
		accounts["Bob"] = bob
	}
	if charlie != nil {
		accounts["Charlie"] = charlie
	}

	fmt.Println("\n 区块链系统已启动 (支持交易签名验证)")

	for {
		printMenu()
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1": // 创建账户
			fmt.Print("请输入账户标签: ")
			label, _ := reader.ReadString('\n')
			label = strings.TrimSpace(label)

			fmt.Print("请输入初始余额: ")
			balanceStr, _ := reader.ReadString('\n')
			balance, err := strconv.Atoi(strings.TrimSpace(balanceStr))
			if err != nil {
				fmt.Println("无效的余额")
				continue
			}

			newAcc := bc.CreateAccount(label, balance)
			if newAcc != nil {
				accounts[label] = newAcc
			}

		case "2": // 发起交易
			// 显示可用账户
			fmt.Println("\n可用账户:")
			for label := range accounts {
				fmt.Printf("- %s\n", label)
			}

			fmt.Print("请选择发送方账户: ")
			fromLabel, _ := reader.ReadString('\n')
			fromLabel = strings.TrimSpace(fromLabel)

			fromAcc, exists := accounts[fromLabel]
			if !exists {
				fmt.Printf("账户不存在: %s\n", fromLabel)
				continue
			}

			fmt.Print("请输入接收方地址: ")
			to, _ := reader.ReadString('\n')
			to = strings.TrimSpace(to)

			fmt.Print("请输入交易金额: ")
			amountStr, _ := reader.ReadString('\n')
			amount, err := strconv.Atoi(strings.TrimSpace(amountStr))
			if err != nil {
				fmt.Println("无效的金额")
				continue
			}

			bc.AddTransaction(fromAcc, to, amount)

		case "3": // 查看交易池
			bc.PrintTxPool()

		case "4": // 生成新区块
			if len(bc.TxPool) == 0 {
				fmt.Println("交易池为空，无法生成新区块")
				continue
			}

			newBlock := bc.GenerateBlock()
			if newBlock.Index > 0 {
				fmt.Printf("\n生成新区块 #%d\n", newBlock.Index)
				fmt.Printf("  包含交易数: %d\n", len(newBlock.Transactions))
				fmt.Printf("  Merkle根: %s\n", newBlock.MerkleRoot)
				fmt.Printf("  区块哈希: %s\n", newBlock.Hash)

				fmt.Print("是否添加到区块链? (y/n): ")
				confirm, _ := reader.ReadString('\n')
				confirm = strings.TrimSpace(confirm)
				if strings.ToLower(confirm) == "y" {
					bc.AddBlock(newBlock)
				} else {
					fmt.Println("区块未添加")
				}
			}

		case "5": // 查看区块链
			bc.PrintBlocks()

		case "6": // 查看账户列表AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
			bc.PrintAccounts()

		case "7": // 查询账户状态
			fmt.Print("请输入账户地址: ")
			address, _ := reader.ReadString('\n')
			address = strings.TrimSpace(address)
			bc.PrintAccountState(address)

		case "8": // 退出系统
			fmt.Println("感谢使用区块链系统，再见!")
			return

		default:
			fmt.Println("无效选择，请重新输入")
		}
	}
}
