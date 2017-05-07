# TDW Recursion Scanner

This library finds the recursions in code.


```Pawn
forward public func1();
forward public func2();

main() {
	RScan_Run();

	goto ___avoid_recursion;
	func1();
___avoid_recursion:

}

func1() {
	func2();
}

func2() {
	func1();
}
```
