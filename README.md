# security-group-revisor-lambda
While working with AWS services inside a secure restricted environment, we often need to allow outbound connections for certain AWS services. The problem is that these AWS services have their IP subnets changed unexpectedly and this might prevent the application inside our restricted environment to talk to these AWS services. To solve this, we need a dynamic solution that will monitor current rules and add/remove rules as needed.

This lambda is one such dynamic solution which will continuously revise the configured security group as required, thus allowing applications under restricted environment to function without any interruption.
