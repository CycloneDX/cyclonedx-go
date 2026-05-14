package cyclonedx

// Validator interface describes BOM validator
type Validator interface {
	Validate(BOM) (error, []error)
}
