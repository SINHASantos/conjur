#!/bin/bash

# Conjur Development Server Mini CLI
# Usage: ./test_conjur.sh [command] [options]

set -e

# Configuration
CONJUR_URL="http://localhost:3000"
CONJUR_ACCOUNT="cucumber"
ADMIN_USER="admin"
ALICE_USER="alice"

# API keys will be fetched dynamically
ADMIN_API_KEY=""
ALICE_API_KEY=""

# Clear any cached keys on script start
unset ADMIN_API_KEY ALICE_API_KEY

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables for tokens
ADMIN_TOKEN=""
ALICE_TOKEN=""

# Function to print section headers
print_section() {
    echo -e "\n${GREEN}=== $1 ===${NC}"
}

# Function to execute curl with nice formatting
execute_curl() {
    local description="$1"
    shift
    echo -e "\n${YELLOW}$description${NC}"
    echo "Command: curl $*"
    echo "Response:"
    curl -s "$@" | jq '.' 2>/dev/null || curl -s "$@"
    echo ""
}

# Function to execute curl with detailed output (headers, status, etc.)
execute_curl_detailed() {
    local description="$1"
    shift
    echo -e "\n${YELLOW}$description${NC}"
    echo "Command: curl -i $*"
    echo ""
    
    # Create temp files for response parts
    local response_file=$(mktemp)
    local headers_file=$(mktemp)
    
    # Execute curl with verbose output
    local http_code=$(curl -s -w "%{http_code}" -D "$headers_file" -o "$response_file" "$@")
    
    # Display HTTP status
    echo -e "${BLUE}HTTP Status: $http_code${NC}"
    
    # Display headers
    echo -e "\n${GREEN}Response Headers:${NC}"
    cat "$headers_file" | grep -v "^$" | while IFS= read -r line; do
        echo "  $line"
    done
    
    # Display response body
    echo -e "\n${GREEN}Response Body:${NC}"
    if [[ -s "$response_file" ]]; then
        # Try to format as JSON first, fallback to plain text
        if jq '.' "$response_file" 2>/dev/null; then
            :  # jq succeeded
        else
            cat "$response_file"
        fi
    else
        echo "  (empty response)"
    fi
    
    # Cleanup
    rm -f "$response_file" "$headers_file"
    echo ""
}

# Function to get API key from Conjur container
get_api_key() {
    local user="$1"
    echo -e "${YELLOW}Fetching API key for $user from Conjur container...${NC}" >&2
    
    # Try to get the API key from the container
    local api_key=$(docker compose exec -T conjur conjurctl role retrieve-key "$CONJUR_ACCOUNT:user:$user" 2>/dev/null | grep -o '[a-z0-9]\{55\}')
    
    if [[ -z "$api_key" || "$api_key" == *"ERROR"* ]]; then
        echo -e "${RED}Failed to retrieve API key for $user from container${NC}" >&2
        echo -e "${YELLOW}You may need to recreate the user or check container status${NC}" >&2
        return 1
    fi
    
    echo "$api_key"
}

# Function to ensure we have API key for user
ensure_api_key() {
    local user="$1"
    
    # Check if we already have the key
    local current_key=""
    if [[ "$user" == "admin" ]]; then
        current_key="$ADMIN_API_KEY"
    elif [[ "$user" == "alice" ]]; then
        current_key="$ALICE_API_KEY"
    fi
    
    if [[ -z "$current_key" ]]; then
        local api_key=$(get_api_key "$user")
        if [[ $? -eq 0 ]]; then
            # Set the variable
            if [[ "$user" == "admin" ]]; then
                ADMIN_API_KEY="$api_key"
            elif [[ "$user" == "alice" ]]; then
                ALICE_API_KEY="$api_key"
            fi
            echo -e "${GREEN}✓ Got API key for $user${NC}"
        else
            return 1
        fi
    fi
}

# Function to get authentication token
get_token() {
    local user="$1"
    local api_key="$2"
    
    if [[ -z "$api_key" ]]; then
        echo -e "${RED}Error: API key is empty for user $user${NC}" >&2
        return 1
    fi
    
    
    local raw_token=$(curl -s -X POST "$CONJUR_URL/authn/$CONJUR_ACCOUNT/$user/authenticate" -d "$api_key")
    
    if [[ -z "$raw_token" ]]; then
        echo -e "${RED}Error: Failed to get authentication token for $user${NC}" >&2
        return 1
    fi
    
    echo "$raw_token" | base64 -w 0
}

# Function to show usage
show_usage() {
    echo -e "${BLUE}Conjur Development Server Mini CLI${NC}"
    echo -e "${YELLOW}Server: $CONJUR_URL | Account: $CONJUR_ACCOUNT${NC}"
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  health                    - Check server health"
    echo "  info                      - Get server info"
    echo "  auth [admin|alice]        - Authenticate user and show token"
    echo "  whoami [admin|alice]      - Show current user identity"
    echo "  roles                     - List all roles"
    echo "  role [admin|alice]        - Get specific role info"
    echo "  policies                  - List policies"
    echo "  cert-status               - Check certificate auth status"
    echo "  cert-test [cert_file]     - Test certificate authentication"
    echo "  custom [endpoint] [method] [data] - Make custom request with headers"
    echo "  rotate-key [admin|alice]  - Rotate API key for user"
    echo "  all                       - Run all basic tests"
    echo ""
    echo "Options:"
    echo "  -u, --url URL            - Override Conjur URL (default: $CONJUR_URL)"
    echo "  -a, --account ACCOUNT    - Override account (default: $CONJUR_ACCOUNT)"
    echo "  -v, --verbose            - Show curl commands"
    echo "  -h, --help               - Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 health"
    echo "  $0 auth admin"
    echo "  $0 whoami alice"
    echo "  $0 custom /health GET"
    echo "  $0 custom /authn-cert/my-service/cucumber/status"
    echo "  $0 cert-test client.crt"
}

# Command functions
cmd_health() {
    local curl_args=("-X" "GET" "$CONJUR_URL/health")
    if [[ -n "$ADMIN_TOKEN" ]]; then
        curl_args+=("-H" "Authorization: Token token=\"$ADMIN_TOKEN\"")
    fi
    execute_curl_detailed "Check server health" "${curl_args[@]}"
}

cmd_info() {
    local curl_args=("-X" "GET" "$CONJUR_URL/info")
    if [[ -n "$ADMIN_TOKEN" ]]; then
        curl_args+=("-H" "Authorization: Token token=\"$ADMIN_TOKEN\"")
    fi
    execute_curl_detailed "Get server info" "${curl_args[@]}"
}

cmd_auth() {
    local user="${1:-admin}"
    
    case "$user" in
        admin|alice) ;;
        *) echo -e "${RED}Error: Unknown user '$user'. Use 'admin' or 'alice'${NC}"; return 1 ;;
    esac
    
    # Ensure we have the API key
    ensure_api_key "$user" || return 1
    
    # Get the API key
    local api_key=""
    if [[ "$user" == "admin" ]]; then
        api_key="$ADMIN_API_KEY"
    else
        api_key="$ALICE_API_KEY"
    fi
    
    echo -e "${YELLOW}Authenticating as $user...${NC}"
    local token=$(get_token "$user" "$api_key")
    
    if [[ $? -ne 0 || -z "$token" ]]; then
        echo -e "${RED}Failed to authenticate as $user${NC}"
        return 1
    fi
    
    if [[ "$user" == "admin" ]]; then
        ADMIN_TOKEN="$token"
    else
        ALICE_TOKEN="$token"
    fi
    
    echo -e "${GREEN}✓ Authentication successful${NC}"
    echo "Token: $token"
}

cmd_whoami() {
    local user="${1:-admin}"
    local token=""
    
    case "$user" in
        admin) 
            [[ -z "$ADMIN_TOKEN" ]] && cmd_auth admin
            token="$ADMIN_TOKEN"
            ;;
        alice) 
            [[ -z "$ALICE_TOKEN" ]] && cmd_auth alice
            token="$ALICE_TOKEN"
            ;;
        *) echo -e "${RED}Error: Unknown user '$user'. Use 'admin' or 'alice'${NC}"; return 1 ;;
    esac
    
    execute_curl_detailed "Whoami as $user" \
        -X GET "$CONJUR_URL/whoami" \
        -H "Authorization: Token token=\"$token\""
}

cmd_roles() {
    [[ -z "$ADMIN_TOKEN" ]] && cmd_auth admin
    execute_curl_detailed "List all roles" \
        -X GET "$CONJUR_URL/roles/$CONJUR_ACCOUNT" \
        -H "Authorization: Token token=\"$ADMIN_TOKEN\""
}

cmd_role() {
    local user="${1:-admin}"
    [[ -z "$ADMIN_TOKEN" ]] && cmd_auth admin
    
    case "$user" in
        admin|alice) ;;
        *) echo -e "${RED}Error: Unknown user '$user'. Use 'admin' or 'alice'${NC}"; return 1 ;;
    esac
    
    execute_curl_detailed "Get $user role info" \
        -X GET "$CONJUR_URL/roles/$CONJUR_ACCOUNT/user/$user" \
        -H "Authorization: Token token=\"$ADMIN_TOKEN\""
}

cmd_policies() {
    [[ -z "$ADMIN_TOKEN" ]] && cmd_auth admin
    execute_curl_detailed "List policies" \
        -X GET "$CONJUR_URL/policies/$CONJUR_ACCOUNT" \
        -H "Authorization: Token token=\"$ADMIN_TOKEN\""
}

cmd_cert_status() {
    execute_curl_detailed "Certificate auth status" \
        -X GET "$CONJUR_URL/authn-cert/my-service/$CONJUR_ACCOUNT/status"
}

cmd_cert_test() {
    local cert_file="$1"
    if [[ -z "$cert_file" ]]; then
        echo -e "${RED}Error: Certificate file required${NC}"
        echo "Usage: $0 cert-test <cert_file>"
        return 1
    fi
    
    if [[ ! -f "$cert_file" ]]; then
        echo -e "${RED}Error: Certificate file '$cert_file' not found${NC}"
        return 1
    fi
    
    execute_curl_detailed "Test certificate authentication" \
        -X POST "$CONJUR_URL/authn-cert/my-service/$CONJUR_ACCOUNT/authenticate" \
        --cert "$cert_file"
}

cmd_custom() {
    local endpoint="$1"
    local method="${2:-GET}"
    local data="$3"
    
    if [[ -z "$endpoint" ]]; then
        echo -e "${RED}Error: Endpoint required${NC}"
        echo "Usage: $0 custom <endpoint> [method] [data]"
        echo "Examples:"
        echo "  $0 custom /health"
        echo "  $0 custom /authn-cert/my-service/cucumber/status GET"
        echo "  $0 custom /policies/cucumber POST '{\"policy\":\"...\"}"
        return 1
    fi
    
    # Add leading slash if missing
    [[ "$endpoint" != /* ]] && endpoint="/$endpoint"
    
    # Build curl arguments
    local curl_args=()
    curl_args+=("-X" "$method")
    curl_args+=("$CONJUR_URL$endpoint")
    
    # Add authentication for most endpoints (except some auth endpoints)
    if [[ ! "$endpoint" =~ ^/authn.*authenticate$ ]]; then
        [[ -z "$ADMIN_TOKEN" ]] && cmd_auth admin
        curl_args+=("-H" "Authorization: Token token=\"$ADMIN_TOKEN\"")
    fi
    
    # Add data if provided
    if [[ -n "$data" ]]; then
        curl_args+=("-H" "Content-Type: application/json")
        curl_args+=("-d" "$data")
    fi
    
    execute_curl_detailed "Custom $method request to $endpoint" "${curl_args[@]}"
}

cmd_rotate_key() {
    local user="${1:-admin}"
    
    case "$user" in
        admin|alice) ;;
        *) echo -e "${RED}Error: Unknown user '$user'. Use 'admin' or 'alice'${NC}"; return 1 ;;
    esac
    
    echo -e "${YELLOW}Note: API key rotation requires manual intervention${NC}"
    echo -e "${YELLOW}Current API key for $user:${NC}"
    
    # Get current key
    local current_key=$(docker compose exec -T conjur conjurctl role retrieve-key "$CONJUR_ACCOUNT:user:$user" 2>/dev/null | tr -d '\r')
    
    if [[ -z "$current_key" || "$current_key" == *"ERROR"* ]]; then
        echo -e "${RED}Failed to retrieve current API key for $user${NC}"
        return 1
    fi
    
    echo "Current API key: $current_key"
    echo ""
    echo -e "${BLUE}To rotate the API key, you would need to:${NC}"
    echo "1. Delete and recreate the user, or"
    echo "2. Use the Conjur API to rotate the key, or" 
    echo "3. Use conjurctl role reset-password (interactive)"
    echo ""
    echo -e "${YELLOW}For now, refreshing cached key...${NC}"
    
    # Update our cached key with current key
    if [[ "$user" == "admin" ]]; then
        ADMIN_API_KEY="$current_key"
        ADMIN_TOKEN=""  # Clear cached token
    else
        ALICE_API_KEY="$current_key"
        ALICE_TOKEN=""  # Clear cached token
    fi
    
    echo -e "${GREEN}✓ Refreshed cached API key for $user${NC}"
}

cmd_all() {
    echo -e "${BLUE}=== Running All Basic Tests ===${NC}"
    cmd_health
    cmd_info
    cmd_auth admin
    cmd_auth alice
    cmd_whoami admin
    cmd_whoami alice
    cmd_roles
    cmd_role admin
    cmd_role alice
    cmd_policies
    cmd_cert_status
    echo -e "\n${GREEN}=== All Tests Complete ===${NC}"
}

# Parse command line arguments
VERBOSE=false
COMMAND=""
ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--url)
            CONJUR_URL="$2"
            shift 2
            ;;
        -a|--account)
            CONJUR_ACCOUNT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        -*)
            echo -e "${RED}Error: Unknown option $1${NC}"
            show_usage
            exit 1
            ;;
        *)
            if [[ -z "$COMMAND" ]]; then
                COMMAND="$1"
            else
                ARGS+=("$1")
            fi
            shift
            ;;
    esac
done

# Show usage if no command provided
if [[ -z "$COMMAND" ]]; then
    show_usage
    exit 0
fi

# Execute command
case "$COMMAND" in
    health) cmd_health ;;
    info) cmd_info ;;
    auth) cmd_auth "${ARGS[0]}" ;;
    whoami) cmd_whoami "${ARGS[0]}" ;;
    roles) cmd_roles ;;
    role) cmd_role "${ARGS[0]}" ;;
    policies) cmd_policies ;;
    cert-status) cmd_cert_status ;;
    cert-test) cmd_cert_test "${ARGS[0]}" ;;
    custom) cmd_custom "${ARGS[0]}" "${ARGS[1]}" "${ARGS[2]}" ;;
    rotate-key) cmd_rotate_key "${ARGS[0]}" ;;
    all) cmd_all ;;
    *)
        echo -e "${RED}Error: Unknown command '$COMMAND'${NC}"
        show_usage
        exit 1
        ;;
esac
