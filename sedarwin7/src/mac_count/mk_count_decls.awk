{
	printf "MAKE_COUNTER(" $2 ");\n"
	if ($1 == "int")
		printf "MAKE_RETSYSCTL(" $2 ");\n"
}
