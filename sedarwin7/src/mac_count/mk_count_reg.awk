{
	printf "REG_COUNTER(" $2 ");\n"
	if ($1 == "int")
		printf "REG_RETSYSCTL(" $2 ");\n"
}
