use vulnclaw_tui::skills::catalog::skill_tree;

#[test]
fn exposes_vulnclaw_workflow_as_parent_nodes() {
    let skills = skill_tree();

    assert_eq!(skills.len(), 4);
    assert_eq!(skills[0].name, "Recon");
    assert_eq!(skills[1].name, "Scan");
    assert_eq!(skills[2].name, "Exploit");
    assert_eq!(skills[3].name, "Report");
    for node in &skills {
        assert!(!node.children.is_empty());
    }
}
