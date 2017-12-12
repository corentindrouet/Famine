EXEC		=	famine
SRC			=	famine.s \
				update_mmaped_file32.s \
				update_mmaped_file.s \
				treat_file.s
OBJ			=	$(SRC:.s=.o)
NASM		=	nasm
NASMFLAGS	=	-f elf64
LINKER		=	ld

$(EXEC): $(OBJ)
	$(info Compiling $(EXEC))
	$(LINKER) -o $@ $^

all: $(EXEC)

%.o: %.s
	$(info Compiling $< into $@ ...)
	@$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	$(info Cleaning . and ./libft ...)
	rm -f $(OBJ)
	$(info Done !)

fclean: clean
	$(info Cleaning . and ./libft ...)
	@rm -rf $(EXEC)
	$(info Done !)

re: fclean all

.PHONY: all clean fclean re
