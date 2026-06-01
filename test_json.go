package main
import (
	"encoding/json"
	"fmt"
)
func main() {
	var x interface{}
	err := json.Unmarshal([]byte(`{"a":1}` + "\x00\x00"), &x)
	fmt.Printf("Error: %v\n", err)
	
	err = json.Unmarshal([]byte(`{"a":1}` + "   "), &x)
	fmt.Printf("Error with spaces: %v\n", err)
}
