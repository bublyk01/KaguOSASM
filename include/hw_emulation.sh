# Functions emulated in this file:
#       read_from_address
#       write_to_address
#       copy_from_to_address
#       dump_RAM_to_file
#       cpu_exec
#       jump_next
#       jump
#       jump_if
#       jump_if_not
#       jump_err
#       jump_print_debug_info

# Read value from RAM
# INPUT: RAM line number
function read_from_address {
    local LINE_NO="${1}"
    # Check if line number is valid e.g. is not outside the range [1, GLOBAL_RAM_SIZE] :
    if [ "${LINE_NO}" -lt 1 ] || [ "${LINE_NO}" -gt ${GLOBAL_RAM_SIZE} ]; then
        exit_fatal "Access to an invalid address ${1}. This may be caused by an incorrect instruction (use -j for debugging) or insufficient GLOBAL_RAM_SIZE (adjust include/system.sh). System halted!"
    fi

    echo "${HW_RAM_MEMORY[${LINE_NO}]}"
}


# Write value to RAM
# INPUT: RAM line number, value to write
function write_to_address {
    local LINE_NO="${1}"
    local VALUE="${2}"

    # Check if line number is valid e.g. is not outside the range [1, GLOBAL_RAM_SIZE].
    if [ "${LINE_NO}" -lt 1 ] || [ "${LINE_NO}" -gt ${GLOBAL_RAM_SIZE} ]; then
        exit_fatal "Access to an invalid address ${1}. This may be caused by an incorrect instruction (use -j for debugging) or insufficient GLOBAL_RAM_SIZE (adjust include/system.sh). System halted!"
    fi

    HW_RAM_MEMORY[${LINE_NO}]="$VALUE"
}


# Copy value from one address to another in RAM
# INPUT: source address, destination address
function copy_from_to_address {
    local SRC_ADDRESS=$1
    local DST_ADDRESS=$2
    if [ "${SRC_ADDRESS:0:1}" = "*" ]; then
        SRC_ADDRESS=$(read_from_address ${SRC_ADDRESS:1})
    fi
    if [ "${DST_ADDRESS:0:1}" = "*" ]; then
        DST_ADDRESS=$(read_from_address ${DST_ADDRESS:1})
    fi

    if [ "${SRC_ADDRESS:0:1}" = "@" ]; then
        write_to_address $DST_ADDRESS "${SRC_ADDRESS:1}"
    else
        write_to_address $DST_ADDRESS "$(read_from_address ${SRC_ADDRESS})"
    fi
}

function get_background_color {
    case $1 in
        g|${COLOR_GREEN})       echo "\\e[42m";;
        y|${COLOR_YELLOW})      echo "\\e[43m";;
        r|${COLOR_RED})         echo "\\e[41m";;
        B|${COLOR_BLACK})       echo "\\e[40m";;
        b|${COLOR_BLUE})        echo "\\e[44m";;
        m|${COLOR_MAGENTA})     echo "\\e[45m";;
        c|${COLOR_CYAN})        echo "\\e[46m";;
        w|${COLOR_WHITE})       echo "\\e[47m";;
        *)                      echo "\\e[0m";;
    esac
}
function dump_RAM_to_file {
    printf "%s\n" "${HW_RAM_MEMORY[@]}" > "${GLOBAL_RAM_FILE}"
}

function cpu_exec {
    local REG_OP_VAL="$(read_from_address ${REG_OP})"
    local REG_A_VAL="$(read_from_address ${REG_A})"
    local REG_B_VAL="$(read_from_address ${REG_B})"
    local REG_C_VAL="$(read_from_address ${REG_C})"
    local REG_D_VAL="$(read_from_address ${REG_D})"
    local CMP_RES=""
    write_to_address $REG_ERROR ""

    case "${REG_OP_VAL}" in
        ${OP_ADD})
            write_to_address $REG_RES "$(echo "${REG_A_VAL} + ${REG_B_VAL}" | bc | sed -e 's/^\./0./' -e 's/^-\./-0./')"
            ;;
        ${OP_SUB})
            write_to_address $REG_RES "$(echo "${REG_A_VAL} - ${REG_B_VAL}" | bc | sed -e 's/^\./0./' -e 's/^-\./-0./')"
            ;;
        ${OP_INCR})
            write_to_address $REG_RES "$(echo "${REG_A_VAL} + 1" | bc | sed -e 's/^\./0./' -e 's/^-\./-0./')"
            ;;
        ${OP_DECR})
            write_to_address $REG_RES "$(echo "${REG_A_VAL} - 1" | bc | sed -e 's/^\./0./' -e 's/^-\./-0./')"
            ;;
        ${OP_DIV})
            write_to_address $REG_RES "$((REG_A_VAL / REG_B_VAL))"
            ;;
        ${OP_MOD})
            write_to_address $REG_RES "$((REG_A_VAL % REG_B_VAL))"
            ;;
        ${OP_MUL})
            write_to_address $REG_RES "$(echo "scale=2; ${REG_A_VAL} * ${REG_B_VAL}" | bc | sed -e 's/^\./0./' -e 's/^-\./-0./')"
            ;;
        ${OP_IS_NUM})
            if [[ "$REG_A_VAL" =~ ^-?[0-9]+$ ]] || [[ "$REG_A_VAL" =~ ^-?[0-9]*\.[0-9]+$ ]]; then
                CMP_RES=1
            else
                CMP_RES=0
            fi
            write_to_address $REG_BOOL_RES "$CMP_RES"
            ;;
        ${OP_CMP_EQ})
            if [ "$REG_A_VAL" == "$REG_B_VAL" ]; then
                CMP_RES=1
            else
                CMP_RES=0
            fi
            write_to_address $REG_BOOL_RES "$CMP_RES"
            ;;
        ${OP_CMP_NEQ})
            if [ "$REG_A_VAL" != "$REG_B_VAL" ]; then
                CMP_RES=1
            else
                CMP_RES=0
            fi
            write_to_address $REG_BOOL_RES "$CMP_RES"
            ;;
        ${OP_CMP_LT})
            if [ "$REG_A_VAL" -lt "$REG_B_VAL" ]; then
                CMP_RES=1
            else
                CMP_RES=0
            fi
            write_to_address $REG_BOOL_RES "$CMP_RES"
            ;;
        ${OP_CMP_LE})
            if [ "$REG_A_VAL" -le "$REG_B_VAL" ]; then
                CMP_RES=1
            else
                CMP_RES=0
            fi
            write_to_address $REG_BOOL_RES "$CMP_RES"
            ;;
        ${OP_CONTAINS})
            if [[ "$REG_A_VAL" == *"$REG_B_VAL"* ]]; then
                CMP_RES=1
            else
                CMP_RES=0
            fi
            write_to_address $REG_BOOL_RES "$CMP_RES"
            ;;
        ${OP_GET_LENGTH})
            write_to_address $REG_RES "${#REG_A_VAL}"
            ;;
        ${OP_STARTS_WITH})
            if [[ "$REG_A_VAL" == "$REG_B_VAL"* ]]; then
                CMP_RES=1
            else
                CMP_RES=0
            fi
            write_to_address $REG_BOOL_RES "$CMP_RES"
            write_to_address $REG_RES "${REG_A_VAL#"$REG_B_VAL"}"
            ;;
        ${OP_GET_COLUMN})
            if [ -z "$REG_C_VAL" ]; then
                COLUMN_VAL=${REG_A_VAL:$((REG_B_VAL - 1)):1}
            else
                COLUMN_VAL=$(echo "${REG_A_VAL}" | awk -F"${REG_C_VAL}" '{print $'"${REG_B_VAL}"'}')
            fi
            write_to_address $REG_RES "$COLUMN_VAL"
            ;;
        ${OP_REPLACE_COLUMN})
            if [ -z "$REG_C_VAL" ]; then
                local INDEX=$((REG_B_VAL - 1))
                REPLACED_STR="${REG_A_VAL:0:INDEX}${REG_D_VAL}${REG_A_VAL:INDEX+1}"
            else
                REPLACED_STR=$(echo "${REG_A_VAL}" | awk -F"${REG_C_VAL}" 'BEGIN { OFS = FS } {$'${REG_B_VAL}'="'${REG_D_VAL}'"}1' )
            fi
            write_to_address $REG_RES "$REPLACED_STR"
            ;;
        ${OP_CONCAT_WITH})
            write_to_address $REG_RES "${REG_A_VAL}${REG_C_VAL}${REG_B_VAL}"
            ;;
        ${OP_READ_INPUT})
            case $REG_A_VAL in
                ${KEYBOARD_READ_CHAR})          read -rn 1 INPUT_LINE;;
                ${KEYBOARD_READ_CHAR_SILENTLY}) read -rsn 1 INPUT_LINE;;
                ${KEYBOARD_READ_LINE})          read -r INPUT_LINE;;
                ${KEYBOARD_READ_LINE_SILENTLY}) read -rs INPUT_LINE;;
                *)                              read -r INPUT_LINE;;
            esac
            write_to_address $KEYBOARD_BUFFER "${INPUT_LINE}"
            ;;
        ${OP_DISPLAY}|${OP_DISPLAY_LN})
            local TEXT_VAL="$(read_from_address ${DISPLAY_BUFFER})"
            local COLOR_VAL="$(read_from_address ${DISPLAY_COLOR})"
            case "${COLOR_VAL}" in
                $COLOR_GREEN)
                    START_COLOR="\033[92m"
                    END_COLOR="\033[0m"
                    ;;
                $COLOR_YELLOW)
                    START_COLOR="\033[93m"
                    END_COLOR="\033[0m"
                    ;;
                $COLOR_RED)
                    START_COLOR="\033[91m"
                    END_COLOR="\033[0m"
                    ;;
                $COLOR_BLACK)
                    START_COLOR="\033[90m"
                    END_COLOR="\033[0m"
                    ;;
                $COLOR_BLUE)
                    START_COLOR="\033[94m"
                    END_COLOR="\033[0m"
                    ;;
                $COLOR_MAGENTA)
                    START_COLOR="\033[95m"
                    END_COLOR="\033[0m"
                    ;;
                $COLOR_CYAN)
                    START_COLOR="\033[96m"
                    END_COLOR="\033[0m"
                    ;;
                $COLOR_WHITE)
                    START_COLOR="\033[97m"
                    END_COLOR="\033[0m"
                    ;;
                *)
                    START_COLOR=""
                    END_COLOR=""
                    ;;
            esac

            if [ "${REG_OP_VAL}" = "${OP_DISPLAY_LN}" ]; then
                echo -e "${START_COLOR}${TEXT_VAL}${END_COLOR}"
            else
                echo -e -n "${START_COLOR}${TEXT_VAL}${END_COLOR}"
            fi
            ;;
        ${OP_READ_BLOCK})
            local DISK_FILE="${SYSTEM_HW_DIR}/${REG_A_VAL}"
            if [ ! -f "$DISK_FILE" ]; then
                write_to_address $REG_ERROR "Disk ${REG_A_VAL} does not exist"
            else
                local BLOCK_COUNT=$(sed -n 1'p' ${DISK_FILE})
                if [[ ! "$BLOCK_COUNT" =~ ^[0-9]+$ ]]; then
                    write_to_address $REG_ERROR "Disk ${REG_A_VAL} is corrupted. First block should contain block count."
                elif [ "$REG_B_VAL" -gt "$BLOCK_COUNT" ] || [ "$REG_B_VAL" -lt 1 ]; then
                    write_to_address $REG_ERROR "Block number ${REG_B_VAL} does not exist"
                else
                    write_to_address $REG_RES "$(sed -n $REG_B_VAL'p' $DISK_FILE)"
                fi
            fi
            ;;
        ${OP_WRITE_BLOCK})
            local DISK_FILE="${SYSTEM_HW_DIR}/${REG_A_VAL}"

            if [ ! -f "$DISK_FILE" ]; then
                write_to_address $REG_ERROR "Disk ${REG_A_VAL} does not exist"
            else
                local BLOCK_COUNT=$(sed -n 1'p' ${DISK_FILE})
                if [[ ! "$BLOCK_COUNT" =~ ^[0-9]+$ ]]; then
                    write_to_address $REG_ERROR "Disk ${REG_A_VAL} is corrupted. First block should contain block count."
                elif [ "$REG_B_VAL" -gt "$BLOCK_COUNT" ] || [ "$REG_B_VAL" -lt 1 ]; then
                    write_to_address $REG_ERROR "Block number ${REG_B_VAL} does not exist"
                elif [ "$REG_B_VAL" -eq 1 ]; then
                    write_to_address $REG_ERROR "Block 1 is read-only"
                else
                    if [[ "$OSTYPE" == "darwin"* ]]; then
                        sed -i '' "${REG_B_VAL}s|.*|$(printf '%s\n' "$REG_C_VAL" | sed 's/[&/\]/\\&/g')|" "${DISK_FILE}"
                    else
                        sed -i "${REG_B_VAL}s|.*|$(printf '%s\n' "$REG_C_VAL" | sed 's/[&/\]/\\&/g')|" "${DISK_FILE}"
                    fi
                fi
            fi
            ;;
        ${OP_SET_BACKGROUND_COLOR})
            echo -e $(get_background_color $(read_from_address ${DISPLAY_BACKGROUND}))
            clear
            ;;
        ${OP_RENDER_BITMAP})
            local RES_STR=""
            local BG_COLOR=$(get_background_color $(read_from_address ${DISPLAY_BACKGROUND}))
            for ((i=$REG_A_VAL;i<$REG_B_VAL;i++)); do
                local CUR_BITMAP_LINE=$(read_from_address $(($i)))
                RES_STR="$RES_STR${CUR_BITMAP_LINE}\n"
            done
            RES_STR="$(echo "$RES_STR" | sed -e 's,m,\\e[45m ,g' -e 's,g,\\e[42m ,g' -e 's,y,\\e[43m ,g' -e 's,r,\\e[41m ,g' -e 's,B,\\e[40m ,g' -e 's,b,\\e[44m ,g' -e 's,c,\\e[46m ,g' -e 's,w,\\e[47m ,g')$BG_COLOR"
            clear
            echo -e "$RES_STR"
            ;;
        ${OP_ENCRYPT_DATA})
            local ENCRYPTED_DATA="${REG_A_VAL}"
            write_to_address $REG_RES "${ENCRYPTED_DATA}"
            ;;
        ${OP_DECRYPT_DATA})
            local DECRYPTED_DATA="${REG_A_VAL}"
            write_to_address $REG_RES "${DECRYPTED_DATA}"
            ;;
        ${OP_NOP})
            sleep ${REG_A_VAL}
            ;;
        ${OP_UNKNOWN})
            echo "Unknown operation during cpu_exec. Terminated."
            exit 1
            ;;
        ${OP_HALT})
            echo "CPU halt"
            exit 0
            ;;
        *)
            echo "Unknown operation ${REG_OP_VAL} during cpu_exec"
        ;;
        esac
}

# increment jump counter
function jump_next {
    write_to_address ${PROGRAM_COUNTER} "$(($(read_from_address ${PROGRAM_COUNTER}) + 1))"
}


# jump to the provided address.
# INPUT: address to jump
function jump {
    if [ "$#"  -ne 1 ]; then
        echo "FATAL_ERROR: no address provided for jump"
        exit 1
    fi

    local ADDRESS=$1
    if [ "${ADDRESS:0:1}" = '*' ]; then
        ADDRESS=$(read_from_address "${ADDRESS:1}")
    fi
    write_to_address ${PROGRAM_COUNTER} "$((${ADDRESS}-1))"
}


# jump_if is a conditional jump to provided address e.g. it will jump only if REG_BOOL_RES equals to "1"
# INPUT: address to jump to
function jump_if {
    if [ "$(read_from_address ${REG_BOOL_RES})" = "1" ]; then
        jump ${1}
    fi
}

# jump_if_not is a conditional jump to provided address e.g. it will jump only if REG_BOOL_RES equals to "0"
# INPUT: address to jump to
function jump_if_not {
    if [ "$(read_from_address ${REG_BOOL_RES})" = "0" ]; then
        jump ${1}
    fi
}

# jump_err is a conditional jump to provided address e.g. it will jump only if REG_ERROR is not empty
# INPUT: address to jump to
function jump_err {
    if [ ! -z "$(read_from_address ${REG_ERROR})" ]; then
        jump ${1}
    fi
}

# Debug output for current instruction
function jump_print_debug_info {
    local NEXT_CMD_ADDRESS=$(read_from_address ${PROGRAM_COUNTER})
    local NEXT_CMD=$(read_from_address $((${NEXT_CMD_ADDRESS})))
    echo -e "\033[34m[DEBUG] Command ${NEXT_CMD_ADDRESS}:\033[35m ${NEXT_CMD}\033[0m"
}


# export functions to be used everywhere
export -f read_from_address
export -f write_to_address
export -f copy_from_to_address
export -f dump_RAM_to_file
export -f cpu_exec
export -f jump_next
export -f jump
export -f jump_if
export -f jump_if_not
export -f jump_err
export -f jump_print_debug_info
