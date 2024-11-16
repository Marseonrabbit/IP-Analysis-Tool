#!/bin/bash

# Configuration
API_KEY="3dbc013b459f54f7936863d83bcc0cfc35b181159240fb2ac58d518361e249bc" #The tool is created by Vikash kumar 
SLEEP_TIME=15

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Validate IP address format
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Analyze single IP
analyze_ip() {
    local ip=$1
    
    echo -e "\n${YELLOW}═══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}📡 Analyzing IP: $ip ${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}\n"

    # Make API request and store response
    local response=$(curl -s -X GET "https://www.virustotal.com/api/v3/ip_addresses/$ip" \
        -H "x-apikey: $API_KEY")

    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Error: Failed to get data for IP $ip${NC}"
        return 1
    fi

    # Check if we got valid JSON response
    if ! echo "$response" | jq empty 2>/dev/null; then
        echo -e "${RED}❌ Error: Invalid JSON response for IP $ip${NC}"
        return 1
    fi

    # Extract and display key information
    echo -e "${BLUE}🌍 Geographic Information:${NC}"
    echo -e "   Country: $(echo "$response" | jq -r '.data.attributes.country // "Unknown"')"
    echo -e "   Continent: $(echo "$response" | jq -r '.data.attributes.continent // "Unknown"')"
    echo -e "   AS Owner: $(echo "$response" | jq -r '.data.attributes.as_owner // "Unknown"')"
    echo -e "   ASN: $(echo "$response" | jq -r '.data.attributes.asn // "Unknown"')"

    echo -e "\n${BLUE}🔍 Analysis Statistics:${NC}"
    local malicious=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
    local suspicious=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.suspicious // 0')
    local harmless=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.harmless // 0')
    local undetected=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.undetected // 0')

    echo -e "   🔴 Malicious: $malicious"
    echo -e "   🟡 Suspicious: $suspicious"
    echo -e "   🟢 Harmless: $harmless"
    echo -e "   ⚪ Undetected: $undetected"

    # Display reputation score
    local reputation=$(echo "$response" | jq -r '.data.attributes.reputation // "Unknown"')
    echo -e "\n${BLUE}📊 Reputation Score: ${NC}$reputation"

    # Display whois data if available
    local whois=$(echo "$response" | jq -r '.data.attributes.whois // "Not available"')
    if [ "$whois" != "Not available" ]; then
        echo -e "\n${BLUE}📝 WHOIS Information:${NC}"
        echo "$whois" | head -n 5  # Display first 5 lines of WHOIS
    fi

    # Display recent detected URLs if available
    echo -e "\n${BLUE}🌐 Recent Detected URLs:${NC}"
    echo "$response" | jq -r '.data.attributes.last_analysis_results | to_entries[] | 
        select(.value.result != null and .value.result != "clean") | 
        "   ⚠️  \(.key): \(.value.result)"' 2>/dev/null || echo "   No detected URLs"

    # Display network information
    echo -e "\n${BLUE}🔌 Network Information:${NC}"
    echo -e "   Network: $(echo "$response" | jq -r '.data.attributes.network // "Unknown"')"
    
    # Display final assessment
    echo -e "\n${BLUE}📝 Final Assessment:${NC}"
    if [ "$malicious" -gt 0 ] || [ "$suspicious" -gt 0 ]; then
        echo -e "${RED}⚠️  WARNING: This IP has been flagged by security vendors${NC}"
        echo -e "${RED}   - Malicious detections: $malicious${NC}"
        echo -e "${RED}   - Suspicious detections: $suspicious${NC}"
    else
        echo -e "${GREEN}✅ This IP appears to be clean${NC}"
    fi

    echo -e "\n${YELLOW}═══════════════════════════════════════════════════${NC}"
}

# Process IP list from file
process_ip_file() {
    local input_file=$1
    local count=0

    while IFS= read -r ip || [ -n "$ip" ]; do
        # Skip empty lines and comments
        [[ -z "$ip" || "$ip" =~ ^[[:space:]]*# ]] && continue
        
        # Trim whitespace
        ip=$(echo "$ip" | tr -d '[:space:]')
        
        # Validate and analyze IP
        if validate_ip "$ip"; then
            count=$((count + 1))
            analyze_ip "$ip"
            # Wait between requests if more IPs follow
            [ $count -gt 0 ] && sleep "$SLEEP_TIME"
        else
            echo -e "${RED}❌ Invalid IP format: $ip${NC}"
        fi
    done < "$input_file"
}

# Main execution
main() {
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}❌ Error: jq is not installed. Please install it first.${NC}"
        echo "Install command:"
        echo "   Ubuntu/Debian: sudo apt-get install jq"
        echo "   CentOS/RHEL: sudo yum install jq"
        echo "   macOS: brew install jq"
        exit 1
    fi

    # Check API key
    if [ "$API_KEY" = "YOUR_VIRUSTOTAL_API_KEY" ]; then
        echo -e "${RED}❌ Error: Please set your VirusTotal API key in the script${NC}"
        exit 1
    fi

    # Process arguments
    if [ "$1" = "-f" ] && [ -n "$2" ]; then
        if [ -f "$2" ]; then
            process_ip_file "$2"
        else
            echo -e "${RED}❌ Error: File $2 does not exist${NC}"
            exit 1
        fi
    elif [ -n "$1" ]; then
        if validate_ip "$1"; then
            analyze_ip "$1"
        else
            echo -e "${RED}❌ Error: Invalid IP format${NC}"
            exit 1
        fi
    else
        echo "Usage:"
        echo "  Single IP: $0 <ip_address>"
        echo "  Multiple IPs from file: $0 -f <filename>"
        exit 1
    fi
}

# Execute main
main "$@"