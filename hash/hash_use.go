package hash

import (
    "fmt"
    "hash"
    "strconv"
)

// Type Mode
var TypeMode = NewTypeSet[Mode, string](maxMode)

// Type Name
type TypeName interface {
    ~uint | ~int
}

// Type Set
type TypeSet[N TypeName, D any] struct {
    // 最大值
    max N

    // 数据
    names *DataSet[N, D]
}

// New TypeSet
func NewTypeSet[N TypeName, D any](max N) *TypeSet[N, D] {
    return &TypeSet[N, D]{
        max:   max,
        names: NewDataSet[N, D](),
    }
}

// 生成新序列
// Generate new id
func (this *TypeSet[N, D]) Generate() N {
    old := this.max
    this.max++

    return old
}

// 类型名称列表
// name list
func (this *TypeSet[N, D]) Names() *DataSet[N, D] {
    return this.names
}

// Mode type
type Mode uint

func (this Mode) String() string {
    switch this {
        default:
            if TypeMode.Names().Has(this) {
                return (TypeMode.Names().Get(this))()
            }

            return "unknown mode value " + strconv.Itoa(int(this))
    }
}

const (
    unknown Mode = 1 + iota
    maxMode
)

// ================

// 接口
type IHash interface {
    // Sum [输入内容, 其他配置]
    Sum(data []byte, cfg ...any) ([]byte, error)

    // New
    New(cfg ...any) (hash.Hash, error)
}

// 使用
var UseHash = NewDataSet[Mode, IHash]()

// 获取方式
func getHash(name Mode) (IHash, error) {
    if !UseHash.Has(name) {
        err := fmt.Errorf("Hash: Hash type [%s] is error.", name)
        return nil, err
    }

    newHash := UseHash.Get(name)

    return newHash(), nil
}

// Sum
func (this Hash) SumBy(name Mode, cfg ...any) Hash {
    newHash, err := getHash(name)
    if err != nil {
        this.Error = err
        return this
    }

    this.data, this.Error = newHash.Sum(this.data, cfg...)

    return this
}

// New
func (this Hash) NewBy(name Mode, cfg ...any) Hash {
    newHash, err := getHash(name)
    if err != nil {
        this.Error = err
        return this
    }

    this.hash, this.Error = newHash.New(cfg...)

    return this
}
