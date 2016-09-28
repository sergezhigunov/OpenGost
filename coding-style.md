# C# Coding Style

The general rule should follow is "use Visual Studio defaults".

1. Should use [Allman style](http://en.wikipedia.org/wiki/Indent_style#Allman_style) braces, where each brace begins on a new line. A single line statement block can go without braces but the block must be properly indented on its own line and it must not be nested in other statement blocks that use braces. 
2. Should use four spaces of indentation (no tabs).
3. Should use `_camelCase` for internal and private fields and use `readonly` where possible. Prefix instance fields with `_`, static fields with `s_` and thread static fields with `t_`. 
4. Avoid `this.` unless absolutely necessary. 
5. Should always specify the visibility, even if it's the default (i.e. `private string _foo` not `string _foo`).
6. Namespace imports should be specified at the top of the file, *outside* of `namespace` declarations and should be sorted alphabetically, with `System.` namespaces at the top and blank lines between different top level groups.
7. Avoid more than one empty line at any time. For example, do not have two blank lines between members of a type.
8. Avoid spurious free spaces. For example avoid `if (someVar == 0)...`, where the dots mark the spurious free spaces. Consider enabling "View White Space (Ctrl+R, W)" if using Visual Studio, to aid detection.
9. If a file happens to differ in style from these guidelines (e.g. private members are named `m_member` rather than `_member`), the existing style in that file takes precedence.
10. Should only use `var` when it's obvious what the variable type is (i.e. `var stream = new FileStream(...)` not `var stream = OpenStandardInput()`).
11. Should use language keywords instead of BCL types (i.e. `int, string, float` instead of `Int32, String, Single`, etc) for both type references as well as method calls (i.e. `int.Parse` instead of `Int32.Parse`).
12. Should use PascalCasing to name all constant, local variables and fields. The only exception is for interop code where the constant value should exactly match the name and value of the code you are calling via interop.
13. Should use english for comments and XML-documentation.


# Non-C# Coding Style

There is current best guidance is consistency for non code files (XML etc). When editing files, keep new code and changes consistent with the style in the files. For new files, it should conform to the style for that component. Last, if there's a completely new component, anything that is reasonably broadly accepted is fine.

