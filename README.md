## 摘要算法


### 项目介绍

*  常用的摘要 hash 算法
*  算法包括: MD2, MD4, MD5, MD5SHA1, Ripemd160, SHA1, SHA256, SM3(国密)


### 下载安装

~~~go
go get -u github.com/deatil/go-hash
~~~


### 使用

~~~go
package main

import (
    "fmt"
    "github.com/deatil/go-hash/hash"
)

func main() {
    // MD5 结果
    md5Data := hash.MD5("useData").

    fmt.Println("MD5 结果：", md5Data)
}

~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
