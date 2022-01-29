package cyclonedx

type Note struct {
	Locale string       `json:"locale,omitempty" xml:"locale,omitempty"`
	Text   AttachedText `json:"text" xml:"text"`
}

type ReleaseNotes struct {
	Type          string      `json:"type" xml:"type"`
	Title         string      `json:"title,omitempty" xml:"title,omitempty"`
	FeaturedImage string      `json:"featuredImage,omitempty" xml:"featuredImage,omitempty"`
	SocialImage   string      `json:"socialImage,omitempty" xml:"socialImage,omitempty"`
	Description   string      `json:"description,omitempty" xml:"description,omitempty"`
	Timestamp     string      `json:"timestamp,omitempty" xml:"timestamp,omitempty"`
	Aliases       *[]string   `json:"aliases,omitempty" xml:"aliases>alias,omitempty"`
	Tags          *[]string   `json:"tags,omitempty" xml:"tags>tag,omitempty"`
	Resolves      *[]Issue    `json:"resolves,omitempty" xml:"resolves>issue,omitempty"`
	Notes         *[]Note     `json:"notes,omitempty" xml:"notes>note,omitempty"`
	Properties    *[]Property `json:"properties,omitempty" xml:"properties>property,omitempty"`
}
