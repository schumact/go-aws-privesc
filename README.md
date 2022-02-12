# aws-privsec

I wanted to rewrite some attacks (mainly IAM based) from pacu's framework in Go in order to learn a bit more about AWS pentesting and the AWS sdk

This isn't meant to be used as an audit tool and is pretty imcomplete. If someone comes across this and wants an actual supported tool then take a look at https://github.com/RhinoSecurityLabs/pacu.git.

Otherwise, feel free to compile my code and run it or take a look at the code and take whatever you need for your own projects.

I chose 13 of the 21 privesc methods mentioned from this great article https://bishopfox.com/blog/privilege-escalation-in-aws which was based on this great article https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/ and included them in this tool. The remaining methods were a bit more "involved" and I just didn't have the motivation to include them. 

## Usage

```
help // shows all commands

set_config   // can use keys as well
set_user <name of user>
run_module <module_name>
```