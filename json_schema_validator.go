package cyclonedx

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

//go:embed schema/bom-1.2.schema.json
//go:embed schema/bom-1.3.schema.json
//go:embed schema/bom-1.4.schema.json
//go:embed schema/bom-1.5.schema.json
var f embed.FS

var (
	// ErrEnumValueNotAllowed ...
	ErrEnumValueNotAllowed = errors.New("value is not allowed for enum")

	// ErrPatternNotMatched ...
	ErrPatternNotMatched = errors.New("value does not match pattern")

	// ErrRequiredFieldMissing ...
	ErrRequiredFieldMissing = errors.New("required field missing")
)

// JSONSchemaValidator default BOM validator
type JSONSchemaValidator struct{}

// NewJSONSchemaValidator creates a new default BOM validator
func NewJSONSchemaValidator() Validator {
	return &JSONSchemaValidator{}
}

// enumRule represents enum values joined with `,`
type enumRule string

// patternRule represents a RegEx pattern
type patternRule string

func (e enumRule) Match(value string) error {
	av := strings.Split(string(e), ",")
	for _, v := range av {
		if v == value {
			return nil
		}
	}
	return ErrEnumValueNotAllowed
}

func (p patternRule) Match(value string) error {
	re := regexp.MustCompile(string(p))
	if re.MatchString(value) {
		return nil
	}
	return ErrPatternNotMatched
}

type RuleMatcher interface {
	Match(string) error
}

func (j *JSONSchemaValidator) Validate(bom BOM) (error, []error) {
	var errorArr []error

	var filePath string
	switch bom.SpecVersion {
	case 0:
		return fmt.Errorf("%w: specVersion", ErrRequiredFieldMissing), errorArr
	case SpecVersion1_2:
		filePath = "schema/bom-1.2.schema.json"
	case SpecVersion1_3:
		filePath = "schema/bom-1.3.schema.json"
	case SpecVersion1_4:
		filePath = "schema/bom-1.4.schema.json"
	case SpecVersion1_5:
		filePath = "schema/bom-1.5.schema.json"
	default:
		return fmt.Errorf("validator unsupported specVersion: %v", bom.SpecVersion), errorArr
	}

	fileData, err := f.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to load schema: %w", err), errorArr
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(fileData, &schema); err != nil {
		return fmt.Errorf("failed to unmarshal schema: %w", err), errorArr
	}

	bomTagPropertyMap := getBomFields(bom)

	requiredFields, err := getRequiredFromSchema(schema)
	requiredErr := requiredFieldsValidation(requiredFields, bomTagPropertyMap)

	rules, err := getValidationRulesFromSchema(bomTagPropertyMap, schema)
	if err != nil {
		return err, errorArr
	}

	errorArr = validateBomWithRules(bom, rules, bomTagPropertyMap)

	errorArr = append(errorArr, requiredErr...)

	return nil, errorArr
}

func getRequiredFromSchema(schema map[string]interface{}) ([]string, error) {
	requiredFields := []string{}

	required, ok := schema["required"].([]interface{})
	if !ok {
		return requiredFields, nil
	}

	for _, v := range required {
		requiredFields = append(requiredFields, fmt.Sprintf("%v", v))
	}

	return requiredFields, nil
}

func getBomFields(bom BOM) map[string]string {
	tp := reflect.TypeOf(bom)
	v := reflect.ValueOf(bom)

	bomFields := map[string]string{}
	for i := 0; i < tp.NumField(); i++ {
		field := tp.Field(i)
		if v.FieldByName(field.Name).IsZero() {
			continue
		}

		jsonTag := field.Tag.Get("json")
		if jsonTag == "" {
			continue
		}
		st := strings.Split(jsonTag, ",")
		bomFields[st[0]] = field.Name
	}

	return bomFields
}

// getValidationRulesFromSchema returns a map of validation rules for each field in the BOM
// Build RuleMatcher only for fields that are present in the BOM
func getValidationRulesFromSchema(bomFields map[string]string, schema map[string]interface{}) (map[string]RuleMatcher, error) {
	rules := map[string]RuleMatcher{}

	properties, ok := schema["properties"].(map[string]interface{})
	if !ok {
		return rules, fmt.Errorf("no properties in schema")
	}

	for k, _ := range bomFields {
		prop, ok := properties[k].(map[string]interface{})
		if !ok {
			continue
		}

		enum, ok := prop["enum"]
		if ok {
			enumArr := enum.([]interface{})
			var enumStrArr []string
			for _, item := range enumArr {
				enumStrArr = append(enumStrArr, fmt.Sprintf("%v", item))
			}
			rules[k] = enumRule(strings.Join(enumStrArr, ","))
		}

		pattern, ok := prop["pattern"]
		if ok {
			rules[k] = patternRule(fmt.Sprintf("%v", pattern))
		}
	}

	return rules, nil
}

func validateBomWithRules(bom BOM, fieldRules map[string]RuleMatcher, bomTagPropertyMap map[string]string) []error {
	v := reflect.ValueOf(bom)
	var errorArr []error
	for prop, r := range fieldRules {
		structPropName, ok := bomTagPropertyMap[prop]
		if !ok {
			errorArr = append(errorArr, fmt.Errorf("property not found: %s", prop))
			continue
		}
		value := v.FieldByName(structPropName).String()
		if vErr := r.Match(value); vErr != nil {
			errorArr = append(errorArr, fmt.Errorf("%s: %w", prop, vErr))
		}
	}
	return errorArr
}

func requiredFieldsValidation(requiredFields []string, bomTagPropertyMap map[string]string) []error {
	var errorArr []error
	for _, prop := range requiredFields {
		_, ok := bomTagPropertyMap[prop]
		if !ok {
			errorArr = append(errorArr, fmt.Errorf("%s: %w", prop, ErrRequiredFieldMissing))

			continue
		}
	}
	return errorArr

}
