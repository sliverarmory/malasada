package main

import "C"
import "fmt"

//export Hello
func Hello() {
	fmt.Println("hello from go")
}

func main() {}

